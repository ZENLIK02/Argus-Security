"use strict";

const fs = require("fs");
const path = require("path");
const Features = require("../engine/feature_extractor.js");

const root = path.resolve(__dirname, "..");
const core = readCases("datasets/exfiltration_eval_cases.json", "core");
const benign = readCases("datasets/benign_robustness_cases.json", "benign");
const randomized = readCases("datasets/randomized_web_eval_cases.json", "randomized");
const EPOCHS = 100;
const L2 = 0.002;
const reports = [];

for (let fold = 0; fold < 5; fold += 1) {
  const trainingCases = core.concat(benign, randomized.filter((row) => row.testCase.fold !== fold));
  const validationCases = randomized.filter((row) => row.testCase.fold === fold);
  const trainingRows = trainingCases.map(toRow);
  const validationRows = validationCases.map(toRow);
  const model = train(trainingRows);
  const report = evaluate(validationRows, model);
  reports.push({ fold, trainCases: trainingRows.length, validationCases: validationRows.length, ...report });
  console.log(`fold ${fold + 1}/5: ${report.correct}/${validationRows.length}, SAFE FP ${report.safeFalsePositives}/100, fake FN ${report.fakeFalseNegatives}/100, level accuracy ${(report.levelAccuracy * 100).toFixed(2)}%`);
}

const totals = reports.reduce((result, report) => ({
  correct: result.correct + report.correct,
  total: result.total + report.validationCases,
  safeFalsePositives: result.safeFalsePositives + report.safeFalsePositives,
  fakeFalseNegatives: result.fakeFalseNegatives + report.fakeFalseNegatives
}), { correct: 0, total: 0, safeFalsePositives: 0, fakeFalseNegatives: 0 });

const output = {
  name: "Project Argus Randomized Five-Fold Cross-Validation",
  generatedAt: "2026-07-11",
  epochsPerFold: EPOCHS,
  folds: reports,
  totals: { ...totals, levelAccuracy: round(totals.correct / totals.total, 4) }
};
fs.writeFileSync(path.join(root, "tests", "randomized_cv_report.json"), `${JSON.stringify(output, null, 2)}\n`, "utf8");

if (totals.safeFalsePositives > 0 || totals.fakeFalseNegatives > 0 || totals.correct / totals.total < 0.95) {
  console.error(`FAIL cross-validation: ${JSON.stringify(totals)}`);
  process.exit(1);
}
console.log(`PASS five-fold total: ${totals.correct}/${totals.total}, SAFE FP ${totals.safeFalsePositives}/500, fake FN ${totals.fakeFalseNegatives}/500.`);

function readCases(relativePath, corpusType) {
  return JSON.parse(fs.readFileSync(path.join(root, relativePath), "utf8")).cases.map((testCase) => ({ testCase, corpusType }));
}

function toRow(entry) {
  const expected = entry.testCase.expect;
  return {
    id: entry.testCase.id,
    label: entry.testCase.label || expected.level,
    expectedLevel: expected.level,
    x: Features.vectorize(entry.testCase.signals),
    y: Math.max(0, Math.min(1, Number(expected.targetScore) / 100)),
    weight: expected.level === "HIGH_RISK" ? 2.5 : expected.level === "SUSPICIOUS" ? 1.2 : 1
  };
}

function train(rows) {
  const means = Features.FEATURE_NAMES.map((_, index) => average(rows.map((row) => row.x[index])));
  const scales = means.map((mean, index) => Math.sqrt(average(rows.map((row) => (row.x[index] - mean) ** 2))) || 1);
  const data = rows.map((row) => ({ ...row, x: row.x.map((value, index) => (value - means[index]) / scales[index]) }));
  let weights = Array(Features.FEATURE_NAMES.length).fill(0);
  let bias = logit(average(rows.map((row) => row.y)));
  let currentLoss = loss(data, weights, bias);

  for (let epoch = 0; epoch < EPOCHS; epoch += 1) {
    const gradient = gradients(data, weights, bias);
    let learningRate = 0.4;
    let accepted = false;
    while (learningRate >= 0.000001) {
      const nextWeights = weights.map((weight, index) => weight - learningRate * gradient.weights[index]);
      const nextBias = bias - learningRate * gradient.bias;
      const nextLoss = loss(data, nextWeights, nextBias);
      if (nextLoss < currentLoss - 1e-10) {
        weights = nextWeights;
        bias = nextBias;
        currentLoss = nextLoss;
        accepted = true;
        break;
      }
      learningRate /= 2;
    }
    if (!accepted) throw new Error(`Fold training failed to improve at epoch ${epoch + 1}.`);
  }
  return { means, scales, weights, bias };
}

function evaluate(rows, model) {
  let correct = 0;
  let safeFalsePositives = 0;
  let fakeFalseNegatives = 0;
  for (const row of rows) {
    const score = predict(row.x, model);
    const level = score >= 70 ? "HIGH_RISK" : score >= 35 ? "SUSPICIOUS" : "SAFE";
    if (level === row.expectedLevel) correct += 1;
    if (row.label === "SAFE" && score >= 35) safeFalsePositives += 1;
    if (row.label === "FAKE" && score < 35) fakeFalseNegatives += 1;
  }
  return { correct, safeFalsePositives, fakeFalseNegatives, levelAccuracy: round(correct / rows.length, 4) };
}

function predict(values, model) {
  const standardized = values.map((value, index) => (value - model.means[index]) / model.scales[index]);
  return Math.round(sigmoid(dot(model.weights, standardized) + model.bias) * 100);
}

function gradients(data, weights, bias) {
  const weightGradient = Array(weights.length).fill(0);
  let biasGradient = 0;
  const totalWeight = data.reduce((total, row) => total + row.weight, 0);
  for (const row of data) {
    const prediction = sigmoid(dot(weights, row.x) + bias);
    const derivative = row.weight * 2 * (prediction - row.y) * prediction * (1 - prediction);
    row.x.forEach((value, index) => { weightGradient[index] += derivative * value; });
    biasGradient += derivative;
  }
  return {
    weights: weightGradient.map((value, index) => value / totalWeight + 2 * L2 * weights[index]),
    bias: biasGradient / totalWeight
  };
}

function loss(data, weights, bias) {
  const totalWeight = data.reduce((total, row) => total + row.weight, 0);
  const error = data.reduce((total, row) => {
    const difference = sigmoid(dot(weights, row.x) + bias) - row.y;
    return total + row.weight * difference * difference;
  }, 0) / totalWeight;
  return error + L2 * weights.reduce((total, value) => total + value * value, 0);
}

function dot(left, right) {
  return left.reduce((total, value, index) => total + value * right[index], 0);
}

function sigmoid(value) {
  if (value >= 0) return 1 / (1 + Math.exp(-Math.min(value, 40)));
  const exp = Math.exp(Math.max(value, -40));
  return exp / (1 + exp);
}

function logit(value) {
  const bounded = Math.max(0.001, Math.min(0.999, value));
  return Math.log(bounded / (1 - bounded));
}

function average(values) {
  return values.reduce((total, value) => total + value, 0) / Math.max(1, values.length);
}

function round(value, places) {
  const factor = 10 ** places;
  return Math.round(value * factor) / factor;
}
