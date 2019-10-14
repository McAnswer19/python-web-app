import sqlite3
import pandas as pd
import datetime
import argparse
from dateutil.parser import parse


def replace_empty(string):
    """function for replacing location entries in the table with more descriptive text."""
    if string == "" or not string.strip():
        return ("NO LOCATION SPECIFIED")
    else:
        return (string)

if __name__ == "__main__":
    # Connecting to the traffic_db
    db_connection = sqlite3.connect('traffic_db')
    db_cursor = db_connection.cursor()


    # We only want two arguments, and we want them to be a very specific way.
    parser = argparse.ArgumentParser()
    parser.add_argument("start_time", help="format example: '2019-07-24 14:00:18'", type= str, action= "store")
    parser.add_argument("end_time", help="format example: '2019-07-24 14:00:49", type = str, action = "store")


    args = parser.parse_args()
    start_time = parse(args.start_time)
    end_time = parse(args.end_time)

    # Just making sure.
    assert start_time < end_time

    # Getting all observations that have not been undone.
    observations_table = pd.read_sql_query("SELECT * FROM vehicle_observations WHERE undone = 0", db_connection)

    # cleaning up our dataframe. Pretty straightforward.
    observations_table["location"] = observations_table["location"].apply(replace_empty)
    observations_table["time"] = observations_table["time"].apply(parse)

    # Filtering by the provided start and end times.
    observations_table = observations_table[observations_table["time"] > start_time]
    observations_table = observations_table[observations_table["time"] < end_time]


    # We are interested only in number of observations and average occupancy.
    mean_table = observations_table.groupby(["location", "vehicle_type"]).mean()
    count_table = observations_table.groupby(["location", "vehicle_type"]).count()

    # ["iuser_token"] seems to work as a measure of independent counts, but may be buggy later. Keep an eye
    # on this.
    output_table = pd.DataFrame({"Average Occupancy (in percent)": mean_table["occupancy"] * 25,
                                 "Count": count_table["iuser_token"]})

    # Saving to csv.
    output_table.to_csv("Program_1_results.csv", index=True)