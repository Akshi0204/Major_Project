from import_export import resources
from .models import Sheets

class SheetsResource(resources.ModelResource):
    class Meta:
        model = Sheets