import matplotlib.pyplot as plt
import pandas as pd
import numpy as np

if __name__ == "__main__":
    file_path = 'results.csv'
    data = pd.read_csv(file_path)

    # Converting time from nanoseconds to milliseconds for better readability
    data_milliseconds = data.copy()
    time_columns = data.columns[2:]  # Selecting only the time columns, excluding total_time
    data_milliseconds[time_columns] = data[time_columns] / 1e6  # Convert nanoseconds to milliseconds

    # Selecting distinct markers for each line
    markers = ['o', 's', '^', 'D', '>', '<', 'p', '*']

    # Adjusting the x-axis (data size) to have more ticks
    x_ticks = np.unique(data_milliseconds['size'])  # Unique values from the 'size' column
    y_ticks = np.geomspace(data_milliseconds[time_columns].min().min(), data_milliseconds[time_columns].max().max(),
                           num=7)
    # Setting up the plot grid for each time metric
    num_columns = len(time_columns)
    print(num_columns)
    fig, axs = plt.subplots(2, 3, figsize=(8, 6))

    # Plotting each time metric in a separate subplot
    for i, column in enumerate(time_columns):
            j = i // 3
            a = axs[j, i % 3]

            a.plot(data_milliseconds['size'], data_milliseconds[column], label=column, marker=markers[i], color='b')
            a.set_xscale('log')
            a.set_yscale('log')
            a.set_xlabel('Data Size')
            a.set_ylabel('Time (milliseconds)')
            a.set_title(column)
            a.grid(True, which="both", ls="--")
            a.set_xticks(x_ticks)
            a.set_yticks(y_ticks)
            a.get_xaxis().set_major_formatter(plt.FuncFormatter(lambda val, pos: f'{int(val)}'))
            a.get_yaxis().set_major_formatter(plt.FuncFormatter(lambda val, pos: f'{val:.2f}'))

    # Adjust layout for better visibility
    plt.tight_layout()

    # Showing the plot
    plt.show()
