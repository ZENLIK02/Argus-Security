"use strict";

const fs = require("fs");
const path = require("path");
const Features = require("../engine/feature_extractor.js");

const root = path.resolve(__dirname, "..");
const coreCorpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "exfiltration_eval_cases.json"), "utf8"));
const benignCorpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "benign_robustness_cases.json"), "utf8"));
const randomizedCorpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "randomized_web_eval_cases.json"), "utf8"));
const megaCorpus = JSON.parse(fs.readFileSync(path.join(root, "datasets", "mega_calibration_cases.json"), "utf8"));
const outputJson = path.join(root, "engine", "trained_model.json");
const outputJs = path.join(root, "engine", "trained_model.js");
const EPOCHS = 100;
const L2 = 0.002;

if (!Array.isArray(coreCorpus.cases) || coreCorpus.cases.length !== 200 ||
  !Array.isArray(benignCorpus.cases) || benignCorpus.cases.length !== 200 ||
  !Array.isArray(randomizedCorpus.cases) || randomizedCorpus.cases.length !== 1000 ||
  !Array.isArray(megaCorpus.cases) || megaCorpus.cases.length !== 20000) {
  throw new Error("Training requires the core corpora plus 20,000 stratified mega-dataset cases.");
}

const rows = [
  ...coreCorpus.cases.map((testCase) => ({ testCase, corpusType: "core" })),
  ...benignCorpus.cases.map((testCase) => ({ testCase, corpusType: "benign-robustness" })),
  ...randomizedCorpus.cases.map((testCase) => ({ testCase, corpusType: "randomized-web" })),
  ...megaCorpus.cases.map((testCase) => ({ testCase, corpusType: "mega-calibration" }))
].map(({ testCase, corpusType }) => ({
  id: testCase.id,
  corpusType,
  x: Features.vectorize(testCase.signals),
  y: Math.max(0, Math.min(1, Number(testCase.expect.targetScore) / 100)),
  expectedLevel: testCase.expect.level,
  datasetSplit: String(testCase.datasetSplit || "").toUpperCase(),
  sampleWeight: corpusType === "mega-calibration"
    ? (testCase.expect.level === "SAFE" ? 0.05 : 0.02)
    : (testCase.expect.level === "HIGH_RISK" ? 2.5 : testCase.expect.level === "SUSPICIOUS" ? 1.2 : 1)
}));
const training = rows.filter((row) => row.corpusType === "mega-calibration" ? row.datasetSplit === "TRAIN" : stableHash(row.id) % 5 !== 0);
const validation = rows.filter((row) => row.corpusType === "mega-calibration" ? row.datasetSplit === "VALIDATION" : stableHash(row.id) % 5 === 0);
const means = columnMeans(training.map((row) => row.x));
const scales = columnScales(training.map((row) => row.x), means);
const standardizedTraining = training.map((row) => ({ ...row, x: standardize(row.x, means, scales) }));
const standardizedValidation = validation.map((row) => ({ ...row, x: standardize(row.x, means, scales) }));

let weights = Array(Features.FEATURE_NAMES.length).fill(0);
let bias = logit(average(training.map((row) => row.y)));
let currentLoss = loss(standardizedTraining, weights, bias);
const history = [];

for (let epoch = 1; epoch <= EPOCHS; epoch += 1) {
  const gradient = gradients(standardizedTraining, weights, bias);
  let learningRate = 0.4;
  let candidate = null;

  while (learningRate >= 0.000001) {
    const nextWeights = weights.map((weight, index) => weight - learningRate * gradient.weights[index]);
    const nextBias = bias - learningRate * gradient.bias;
    const nextLoss = loss(standardizedTraining, nextWeights, nextBias);
    if (nextLoss < currentLoss - 1e-10) {
      candidate = { weights: nextWeights, bias: nextBias, loss: nextLoss, learningRate };
      break;
    }
    learningRate /= 2;
  }

  if (!candidate) {
    throw new Error(`Training stopped before epoch ${epoch}; no monotonic loss-reducing step was found.`);
  }

  weights = candidate.weights;
  bias = candidate.bias;
  currentLoss = candidate.loss;
  history.push({
    epoch,
    trainLoss: round(currentLoss, 8),
    validationLoss: round(loss(standardizedValidation, weights, bias), 8),
    learningRate: round(candidate.learningRate, 6)
  });
}

const model = {
  name: "Project Argus Local Risk Calibrator",
  version: "4.3.0",
  modelType: "regularized-logistic-calibrator",
  corpusVersion: `${coreCorpus.version}+${benignCorpus.version}+${randomizedCorpus.version}+${megaCorpus.version}`,
  totalCaseCount: rows.length,
  coreCaseCount: coreCorpus.cases.length,
  benignRobustnessCaseCount: benignCorpus.cases.length,
  randomizedCaseCount: randomizedCorpus.cases.length,
  megaCalibrationCaseCount: megaCorpus.cases.length,
  featureCount: Features.FEATURE_NAMES.length,
  featureNames: Features.FEATURE_NAMES,
  means: means.map((value) => round(value, 8)),
  scales: scales.map((value) => round(value, 8)),
  weights: weights.map((value) => round(value, 8)),
  bias: round(bias, 8),
  epochs: EPOCHS,
  trainCaseCount: training.length,
  validationCaseCount: validation.length,
  trainingHistory: history,
  metrics: {
    train: metrics(standardizedTraining, weights, bias),
    validation: metrics(standardizedValidation, weights, bias),
    regressionValidation: metrics(standardizedValidation.filter((row) => row.corpusType !== "mega-calibration"), weights, bias),
    benignValidation: metrics(standardizedValidation.filter((row) => row.corpusType === "benign-robustness"), weights, bias),
    benignAll: metrics(rows.filter((row) => row.corpusType === "benign-robustness").map((row) => ({ ...row, x: standardize(row.x, means, scales) })), weights, bias),
    randomizedValidation: metrics(standardizedValidation.filter((row) => row.corpusType === "randomized-web"), weights, bias),
    randomizedAll: metrics(rows.filter((row) => row.corpusType === "randomized-web").map((row) => ({ ...row, x: standardize(row.x, means, scales) })), weights, bias),
    megaValidation: metrics(standardizedValidation.filter((row) => row.corpusType === "mega-calibration"), weights, bias)
  },
  privacy: "Trained only on synthetic numeric and boolean browser metadata; no page text, credentials, payloads, or browsing history."
};

fs.writeFileSync(outputJson, `${JSON.stringify(model, null, 2)}\n`, "utf8");
fs.writeFileSync(outputJs, `self.ArgusTrainedModel = ${JSON.stringify(model)};\n`, "utf8");
console.log(`Trained ${model.name} for ${EPOCHS} monotonic epochs.`);
console.log(`Cases: ${training.length} train / ${validation.length} validation.`);
console.log(`Loss: ${history[0].trainLoss} -> ${history[history.length - 1].trainLoss}.`);
console.log(`Validation MAE: ${model.metrics.validation.meanAbsoluteError}; level accuracy: ${model.metrics.validation.levelAccuracy}.`);

function gradients(data, currentWeights, currentBias) {
  const weightGradient = Array(currentWeights.length).fill(0);
  let biasGradient = 0;
  const totalSampleWeight = data.reduce((total, row) => total + row.sampleWeight, 0);
  for (const row of data) {
    const prediction = sigmoid(dot(currentWeights, row.x) + currentBias);
    const derivative = row.sampleWeight * 2 * (prediction - row.y) * prediction * (1 - prediction);
    for (let index = 0; index < weightGradient.length; index += 1) {
      weightGradient[index] += derivative * row.x[index];
    }
    biasGradient += derivative;
  }
  for (let index = 0; index < weightGradient.length; index += 1) {
    weightGradient[index] = weightGradient[index] / totalSampleWeight + 2 * L2 * currentWeights[index];
  }
  return { weights: weightGradient, bias: biasGradient / totalSampleWeight };
}

function loss(data, currentWeights, currentBias) {
  if (data.length === 0) return 0;
  const totalSampleWeight = data.reduce((total, row) => total + row.sampleWeight, 0);
  const mse = data.reduce((total, row) => {
    const error = sigmoid(dot(currentWeights, row.x) + currentBias) - row.y;
    return total + row.sampleWeight * error * error;
  }, 0) / totalSampleWeight;
  const penalty = L2 * currentWeights.reduce((total, value) => total + value * value, 0);
  return mse + penalty;
}

function metrics(data, currentWeights, currentBias) {
  let absoluteError = 0;
  let correctLevels = 0;
  let safeCount = 0;
  let safeFalseWarnings = 0;
  let highRiskCount = 0;
  let highRiskDetected = 0;
  let fakeCount = 0;
  let fakeDetected = 0;
  for (const row of data) {
    const score = Math.round(sigmoid(dot(currentWeights, row.x) + currentBias) * 100);
    absoluteError += Math.abs(score / 100 - row.y);
    const predictedLevel = score >= 70 ? "HIGH_RISK" : score >= 35 ? "SUSPICIOUS" : "SAFE";
    if (predictedLevel === row.expectedLevel) correctLevels += 1;
    if (row.expectedLevel === "SAFE") {
      safeCount += 1;
      if (score >= 35) safeFalseWarnings += 1;
    }
    if (row.expectedLevel === "HIGH_RISK") {
      highRiskCount += 1;
      if (score >= 70) highRiskDetected += 1;
    }
    if (row.expectedLevel !== "SAFE") {
      fakeCount += 1;
      if (score >= 35) fakeDetected += 1;
    }
  }
  return {
    meanAbsoluteError: round(absoluteError / Math.max(1, data.length), 4),
    levelAccuracy: round(correctLevels / Math.max(1, data.length), 4),
    safeFalsePositiveRate: round(safeFalseWarnings / Math.max(1, safeCount), 4),
    highRiskRecall: round(highRiskDetected / Math.max(1, highRiskCount), 4),
    fakeDetectionRecall: round(fakeDetected / Math.max(1, fakeCount), 4)
  };
}

function columnMeans(matrix) {
  return Features.FEATURE_NAMES.map((_, index) => average(matrix.map((row) => row[index])));
}

function columnScales(matrix, means) {
  return means.map((mean, index) => {
    const variance = average(matrix.map((row) => (row[index] - mean) ** 2));
    return Math.sqrt(variance) || 1;
  });
}

function standardize(row, means, scales) {
  return row.map((value, index) => (value - means[index]) / scales[index]);
}

function stableHash(value) {
  let hash = 2166136261;
  for (const character of String(value)) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
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
