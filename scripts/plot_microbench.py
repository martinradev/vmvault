import matplotlib.pyplot as plt
import numpy as np
import os

class PlotInfo:
    def __init__(self, x_ticks, x_labels, y_ticks, y_labels, title, x_axis_name, y_axis_name, limit):
        self.x_ticks = x_ticks
        self.x_labels = x_labels
        self.y_ticks = y_ticks
        self.y_labels = y_labels
        self.title = title
        self.x_axis_name = x_axis_name
        self.y_axis_name = y_axis_name
        self.limit = limit

def plot_data(axs, file_name, plot_info):
    results_file = open(file_name, "r")
    num_bytes_x = []
    num_cycles_y = []
    for line in results_file:
        tokens = line.split(" ")
        input_size = int(tokens[0])
        num_cycles = int(tokens[2])
        if input_size > plot_info.limit:
            break
        num_bytes_x.append(input_size)
        num_cycles_y.append(num_cycles)
    results_file.close()

    axs.set(xlabel=plot_info.x_axis_name, ylabel=plot_info.y_axis_name)
    axs.set_xticks(np.array(plot_info.x_ticks))
    axs.set_xticklabels(plot_info.x_labels)
    axs.set_yticks(np.array(plot_info.y_ticks))
    axs.set_yticklabels(plot_info.y_labels)
    axs.set_title(plot_info.title)
    axs.plot(np.array(num_bytes_x), np.array(num_cycles_y))

    axs.vlines(np.array(plot_info.x_ticks), 0,
        np.full(len(plot_info.x_ticks),
        max(plot_info.y_ticks)),
        linestyle="dotted",
        color='gray')

fig, axs = plt.subplots(2, 2)

# Instruction cache
plot_data(axs[0, 0], "/tmp/results-instr-cache.txt",
    PlotInfo(
            x_ticks=[32 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024],
            x_labels=["32", "128", "256", "512", "1024"],
            y_ticks=[1, 4, 8, 16, 20],
            y_labels=["1", "4", "8", "16", "20"],
            title="Instruction cache and latency",
            x_axis_name="Cache size (Kib)",
            y_axis_name="Latency (cycles)",
            limit=1024 * 1024))

# Data cache
plot_data(axs[0, 1], "/tmp/results-data-cache.txt",
    PlotInfo(
            x_ticks=[32 * 1024, 128 * 1024, 256 * 1024, 512 * 1024, 1024 * 1024],
            x_labels=["32", "128", "256", "512", "1024"],
            y_ticks=[1, 4, 8, 16, 20],
            y_labels=["1", "4", "8", "16", "20"],
            title="Data cache and latency",
            x_axis_name="Cache size (Kib)",
            y_axis_name="Latency (cycles)",
            limit=1024 * 1024))

# dTLB
plot_data(axs[1, 0], "/tmp/results-data-page.txt",
    PlotInfo(
            x_ticks=[64, 256, 512, 1024, 2048],
            x_labels=["64", "256", "512", "1024", "2048"],
            y_ticks=[1, 4, 8, 16, 22],
            y_labels=["1", "4", "8", "16", "22"],
            title="dTLB size and latency",
            x_axis_name="Num pages (4 KiB)",
            y_axis_name="Latency (cycles)",
            limit=3000))

# iTLB
plot_data(axs[1, 1], "/tmp/results-instr-page.txt",
    PlotInfo(
            x_ticks=[64, 256, 512, 1024],
            x_labels=["64", "256", "512", "1024"],
            y_ticks=[1, 4, 8, 16, 30],
            y_labels=["1", "4", "8", "16", "30"],
            title="iTLB size and latency",
            x_axis_name="Num pages (4 KiB)",
            y_axis_name="Latency (cycles)",
            limit=2000))

plt.suptitle("mini-svm microbench")

plt.show()
