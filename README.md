# IDA Trace Replayer 

This IDA Plugin can load trace files (text files) generated by the DynamoRIO DBI tool and use the contained basic block address data to visualize the execution of code within the binary.
The trace file contains the RVA of every basic block visited and the plugin allows to step forward/backward, "run to" and also perfom annotation (comments) and basic block coloring to visualize the execution path.

In contrast to tools like "lighthouse" that also take DynamoRIO converage files, the traces for the plugin also contain the order of execution.

### Installation 

git clone into %APPDATA%/Hex-Rays/IDA Pro/plugins

### Usage

- Start IDA Pro and load the binary to analyze

- Select File -> Script file... to run the plugin's '__init__.py' file.

- Click "Load trace" to load the text trace (see example directory for an example trace file)

- Double click a step entry to go to that step, use prev/next to go backwards/forwards. Enter step id and click "Go to" to jump directly to this step

- Enter target step ID and click "Run to" to run from the current step to the target step ID.

- When the checkbox "Auto annotate" is checked, visiting a node will color the node in green and add a comment with the step ID.

### Todo

- Integrate plugin into IDA UI

- Vary color based on number of visits to BB

- Improve the documentation a LOT

### System requirements

Tested with IDA Pro 8.2 under Windows 10 22H2 and Python 3.10. Should work with any decent version of IDA Pro > 7.4

### Thank you

Developed with [IDACode](https://github.com/ioncodes/idacode)



