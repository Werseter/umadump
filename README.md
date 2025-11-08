# Umadump

Dump your veteran list into a JSON file.

Most fields still use IDs instead of direct names, so you'll still need to cross-reference those with the definitions under `master.mdb`.

## Usage

1. Download the executable from the releases tab (or the python script if you have python installed)
2. With the game open, go to the 'Vetern List' page (Enhance -> List)
3. Run the executable

If everything went right, a `data.json` file will be created where you ran the command.

A sample version of the `data.json` file is available [on the project root](/data.json)

## Is this bannable?

The program just reads the game memory. Currently the game does not have any tools to intercept this kind of scan. So no.

## Obs

So far I've only ran this on my machine, and I still need to handle some errors.
