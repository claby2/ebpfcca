import matplotlib.pyplot as plt
import json
import os
import numpy as np
import numpy.typing as npt
NDArray = npt.NDArray[np.float64]


# User-defined options
target_server = "bokaibi.com"
target_port = 5142
total_seconds = 30
report_interval = 0.1
ccas = ["cubic", "bpf_cubic"]
trials = 10
y_unit = "bytes"
use_sum = True
                

class Result:
    def __init__(self, x_arr: NDArray, y_arr: NDArray, cca: str):
        self.x_arr = x_arr
        self.y_arr = y_arr
        self.cca = cca

y_units = ["snd_cwnd", "bytes", "bits_per_second", "retransmits", "rtt"]

def get_xy_array(intervals: list[dict], y_unit: str, use_sum: bool) -> tuple[NDArray, NDArray]:
    # get x&y array from intervals data given, takes 1 json file
    if y_unit not in y_units:
        print("Invalid y_unit")
        return
    if y_unit == "rtt" and use_sum:
        print("Cannot use sum for rtt")
        return
    
    x_arr = np.empty(len(intervals))
    y_arr = np.empty(len(intervals))
    for ind, interval in enumerate(intervals):
        if use_sum:
            analyzed_unit = "sum"
            x = interval[analyzed_unit]["start"]
            y = interval[analyzed_unit][y_unit]
        else:
            analyzed_unit = "streams"
            x = interval[analyzed_unit][0]["start"]
            y = interval[analyzed_unit][0][y_unit]
        x_arr[ind] = x
        y_arr[ind] = y
    
    return (x_arr, y_arr)

notice = input("This script will delete all .json files in the current directory. Do you want to continue? (y/n) ")
if notice != "y" and notice != "Y":
    print("Aborting")
    exit()

print("Running the benchmark for the following CCAs: ", ccas)
print(f"Parameters: target_server={target_server}, target_port={target_port}, total_seconds={total_seconds}, report_interval={report_interval}, trials={trials}")
print(f"Data processing options: y_unit={y_unit}, use_sum={use_sum}")

results = []

for cca in ccas:
    # generate data
    os.system(f"sudo bash benchmark.sh {target_server} {target_port} {total_seconds} {report_interval} {cca} {trials}")

    # process each json file, then delete all of them
    cca_xs = np.empty(trials)
    cca_ys = np.empty(trials)
    for trial in range(1, trials+1):
        file = os.getcwd() + f"\\{cca}_{trial}.json"
        with open(file, "r") as f:
            data = json.load(f)
            intervals = data["intervals"]
            (xs, ys) = get_xy_array(intervals, y_unit, use_sum)
            cca_xs[trial-1] = xs
            cca_ys[trial-1] = ys
        os.remove(file)
    average_xs = np.mean(cca_xs, axis=1)
    average_ys = np.mean(cca_ys, axis=1)
    results.append(Result(average_xs, average_ys, cca))

# Plot the graph
for result in results:
    plt.plot(result.x_arr, result.y_arr, label=result.cca)
plt.xlabel("Time (s)")
plt.ylabel(y_unit)
plt.legend(title = "CCA:")
plt.title(f"CCA Performance, averaged over {trials} trials")
plt.show()
                

