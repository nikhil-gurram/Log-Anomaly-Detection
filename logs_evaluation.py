
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, accuracy_score, confusion_matrix

df = pd.read_csv("web_logs_with_labels.csv")

y_true = df["true_label"]
y_pred = df["predicted_label"]

precision = precision_score(y_true, y_pred)
recall = recall_score(y_true, y_pred)
f1 = f1_score(y_true, y_pred)
accuracy = accuracy_score(y_true, y_pred)

cm = confusion_matrix(y_true, y_pred)
tn, fp, fn, tp = cm.ravel()

print("\n===== METRICS =====")
print(f"Precision : {precision*100:.1f}%")
print(f"Recall    : {recall*100:.1f}%")
print(f"F1 Score  : {f1*100:.1f}%")
print(f"Accuracy  : {accuracy*100:.1f}%")

print("\n===== CONFUSION MATRIX =====")
print(cm)

print("\n===== COUNTS =====")
print(f"TP={tp}, FP={fp}, FN={fn}, TN={tn}")
