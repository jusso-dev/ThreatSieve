export interface LabelledPrediction {
  id: string;
  category: "maliciousness" | "actor";
  label: 0 | 1;
  probability: number;
  humanReview: boolean;
}
/** Wilson score interval, 95%, conditional on independent labelled cases. */
export function wilsonInterval(successes: number, total: number) {
  if (!total) return null;
  const z = 1.959963984540054,
    p = successes / total;
  const denominator = 1 + (z * z) / total;
  const centre = (p + (z * z) / (2 * total)) / denominator;
  const margin =
    (z * Math.sqrt((p * (1 - p)) / total + (z * z) / (4 * total * total))) /
    denominator;
  return {
    lower: Math.max(0, centre - margin),
    upper: Math.min(1, centre + margin),
    cases: total,
  };
}
export function evaluate(predictions: LabelledPrediction[], threshold = 0.5) {
  let tp = 0,
    tn = 0,
    fp = 0,
    fn = 0,
    brier = 0;
  for (const p of predictions) {
    const positive = p.probability >= threshold;
    if (positive && p.label) tp++;
    else if (positive) fp++;
    else if (p.label) fn++;
    else tn++;
    brier += (p.probability - p.label) ** 2;
  }
  let calibrationError = 0;
  for (let bin = 0; bin < 10; bin++) {
    const items = predictions.filter(
      (p) => Math.min(9, Math.floor(p.probability * 10)) === bin,
    );
    if (items.length) {
      const confidence =
        items.reduce((s, p) => s + p.probability, 0) / items.length;
      const frequency = items.reduce((s, p) => s + p.label, 0) / items.length;
      calibrationError +=
        (items.length / Math.max(1, predictions.length)) *
        Math.abs(confidence - frequency);
    }
  }
  const ratio = (n: number, d: number) => (d ? n / d : null);
  return {
    cases: predictions.length,
    uncertainty: {
      method: "95% Wilson; assumes independent representative labels",
      precision: wilsonInterval(tp, tp + fp),
      recall: wilsonInterval(tp, tp + fn),
      false_positive_rate: wilsonInterval(fp, fp + tn),
    },
    precision: ratio(tp, tp + fp),
    recall: ratio(tp, tp + fn),
    false_positive_rate: ratio(fp, fp + tn),
    false_negative_rate: ratio(fn, tp + fn),
    brier_score: ratio(brier, predictions.length),
    calibration_error: predictions.length ? calibrationError : null,
    human_escalation_rate: ratio(
      predictions.filter((p) => p.humanReview).length,
      predictions.length,
    ),
    confusion: {
      true_positive: tp,
      true_negative: tn,
      false_positive: fp,
      false_negative: fn,
    },
  };
}
