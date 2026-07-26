import json

def export_inventory(inventory, filename):
    with open(filename, "w") as inventory_file:
        json.dump(inventory, inventory_file, default=str)
        return filename
