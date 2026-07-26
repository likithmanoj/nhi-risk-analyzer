from nhi.aws.s3 import upload_file
from nhi.services.inventory import create_inventory
from nhi.services.export import export_inventory

inventory = create_inventory()
inventory_file = export_inventory(inventory, "inventory.json")
upload_file(inventory_file)



