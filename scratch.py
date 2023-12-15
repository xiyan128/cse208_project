import numpy as np


def generate_test_data(num_points=50):
    # Generating random points
    data_points = np.random.rand(num_points, 3)

    # Normalizing the points
    normalized_points = data_points / data_points.sum(axis=1, keepdims=True)

    # Decision boundary - for simplicity, let's use the average of the first two features
    # Points with a higher third feature compared to the average of the first two are labeled 1, else 0
    labels = (normalized_points[:, 2] > (normalized_points[:, 0] + normalized_points[:, 1]) / 2).astype(int)

    # Concatenating the labels to the normalized points
    labeled_data = np.hstack((normalized_points, labels.reshape(-1, 1)))

    return labeled_data


if __name__ == "__main__":

    num_points = 512

    # Generate the knn_data
    test_data = generate_test_data(num_points=num_points)

    print(test_data)

    # dump to csv (without header)

    np.savetxt(f"example_{num_points}.csv", test_data, delimiter=",", fmt='%f')

