import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
from scipy.stats import sem
import matplotlib.pyplot as plt

def knn_cosine_similarity(query_point, data_points, labels, k=5):
    # Normalize the query point
    query_point_normalized = query_point / np.linalg.norm(query_point)

    # Compute cosine similarities
    similarities = cosine_similarity([query_point_normalized], data_points)[0]

    # Get indices of k nearest neighbors
    nearest_neighbors_indices = np.argsort(similarities)[-k:]

    # Majority vote for class
    majority_class = np.bincount(labels[nearest_neighbors_indices]).argmax()

    return majority_class


def predict_classes(data_points, train_data, train_labels, k=5):
    predictions = []
    for point in data_points:
        predicted_class = knn_cosine_similarity(point, train_data, train_labels, k)
        predictions.append(predicted_class)
    return predictions


# Redefining the perform_trials_with_labels function for 30 trials and 5% test set size
def perform_trials_with_labels(data, labels, trials=30, test_size=0.05, k=5):
    accuracies = []
    for _ in range(trials):
        # Split the data into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(data, labels, test_size=test_size)

        # Predict and calculate accuracy
        predictions = predict_classes(X_test, X_train, y_train, k)
        accuracy = np.mean(predictions == y_test)
        accuracies.append(accuracy)
    return accuracies

if __name__ == "__main__":
    # Loading all the datasets
    file_paths = {
        "16": 'knn_data/example_16.csv',
        "32": 'knn_data/example_32.csv',
        "64": 'knn_data/example_64.csv',
        "128": 'knn_data/example_128.csv',
        "256": 'knn_data/example_256.csv',
        "512": 'knn_data/example_512.csv'
    }

    # Normalizing data and extracting labels for each dataset
    datasets_labels = {}
    for size, path in file_paths.items():
        data = pd.read_csv(path)
        normalized_points = data.iloc[:, :3].values
        labels = (normalized_points[:, 2] > (normalized_points[:, 0] + normalized_points[:, 1]) / 2).astype(int)
        datasets_labels[size] = (normalized_points, labels)

    # Performing trials for each dataset with 30 tries and 5% test set
    results_30_trials = {size: perform_trials_with_labels(data, labels, trials=200)
                         for size, (data, labels) in datasets_labels.items()}

    # Calculate means and confidence intervals
    means_30_trials = {size: np.mean(acc) for size, acc in results_30_trials.items()}
    cis_30_trials = {size: sem(acc) * 1.96 for size, acc in results_30_trials.items()}  # 95% CI

    # Plotting the results for 30 trials
    sizes_30_trials = sorted(means_30_trials.keys(), key=lambda x: int(x))
    mean_values_30_trials = [means_30_trials[size] for size in sizes_30_trials]
    ci_values_30_trials = [cis_30_trials[size] for size in sizes_30_trials]

    print(mean_values_30_trials)

    plt.figure(figsize=(10, 6))
    plt.errorbar(sizes_30_trials, mean_values_30_trials, fmt='o', ecolor='gray', capsize=5,
                 capthick=2)
    plt.xlabel('Dataset Size')
    plt.ylabel('Accuracy')
    plt.title('KNN Accuracy with Confidence Intervals for Different Dataset Sizes (30 Trials)')
    plt.grid(True)
    plt.show()
