# Umadump

Dump your veteran list into a JSON file.

Most fields still use IDs instead of direct names, so you'll still need to cross-reference those with the definitions under `master.mdb`.
You can use my [UmaDump-JSON-Viewer](https://github.com/Werseter/UmaDump-JSON-Viewer) to browse the dumped data in a human-readable format.

## Usage

1. Download the executable from the releases tab (or the python script if you have python installed)
2. With the game open, go to the 'Veteran List' page (Enhance -> List)
3. Run the executable (as Administrator)

If everything went right, a `umadump_data.json` file will be created where you ran the command.

A sample version of the `umadump_data.json` file is available [on the project root](/umadump_data.json)

## Is this bannable?

The program accesses the game memory by attaching a debugger to it. Currently, the game does not have any tools to intercept this kind of scan. However, using this tool is at your own risk. The author is not responsible for any ban or penalty you may receive from using it.
