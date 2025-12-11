import bleach
from jsonschema import ValidationError, validate
from rest_framework import serializers

from ..models.fichas import Ficha

FICHA_SCHEMA = {
    "type": "object",
    "required": ["nome", "nivel", "atributos", "schema_version"],
    "properties": {
        "nome": {"type": "string"},
        "raca": {"type": "string"},
        "classe": {"type": "string"},
        "nivel": {"type": "integer", "minimum": 1},
        "jogador": {"type": "string"},
        "atributos": {
            "type": "object",
            "properties": {
                "for": {"type": "integer"},
                "des": {"type": "integer"},
                "con": {"type": "integer"},
                "int": {"type": "integer"},
                "sab": {"type": "integer"},
                "car": {"type": "integer"}
            },
            "required": ["for", "des", "con", "int", "sab", "car"]
        },
        "schema_version": {"type": "integer"}
    }
}


class FichaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ficha
        fields = "__all__"
        read_only_fields = ("created_at", "updated_at")

    def validate_nome(self, value):
        # sanitize to avoid XSS when rendering later
        return bleach.clean(value)

    def validate_anotacoes(self, value):
        return bleach.clean(value)

    def validate(self, data):
        # nivel must exist and be >=1
        nivel = data.get("nivel", None)
        if nivel is None or int(nivel) < 1:
            raise serializers.ValidationError({"nivel": "Nível deve ser inteiro >= 1."})
        # atributos exist
        if "atributos" in data:
            attrs = data["atributos"]
            required = {"for", "des", "con", "int", "sab", "car"}
            if not required.issubset(set(attrs.keys())):
                raise serializers.ValidationError({"atributos": "Faltam atributos obrigatórios."})
        return data

    @staticmethod
    def validate_import_json(obj):
        try:
            validate(instance=obj, schema=FICHA_SCHEMA)
        except ValidationError as e:
            raise serializers.ValidationError({"import_json": str(e)})
