from django.core.validators import MinValueValidator
from django.db import models
from django.utils import timezone


class Ficha(models.Model):
    SCHEMA_VERSION = 1

    nome = models.CharField(max_length=200, blank=True)
    raca = models.CharField(max_length=100, blank=True)
    classe = models.CharField(max_length=100, blank=True)
    nivel = models.PositiveIntegerField(default=1, validators=[MinValueValidator(1)], blank=True)
    tendencia = models.CharField(max_length=50, blank=True)
    jogador = models.CharField(max_length=100, blank=True)

    # Atributos base: armazenados como objeto {"for": 10, "des": 10, ...}
    atributos = models.JSONField(default=dict)  # Força, Destreza, Constituição, Inteligência, Sabedoria, Carisma

    # Campos flexíveis: pericias, poderes, magias, inventario, resistencias, etc.
    pericias = models.JSONField(default=list, blank=True)
    poderes = models.JSONField(default=list, blank=True)
    magias = models.JSONField(default=list, blank=True)
    equipamentos = models.JSONField(default=list, blank=True)
    anotacoes = models.TextField(blank=True)

    pv_atual = models.IntegerField(null=True, blank=True)
    pv_max = models.IntegerField(null=True, blank=True)
    defesa = models.CharField(max_length=100, blank=True)
    deslocamento = models.CharField(max_length=100, blank=True)
    resistencias = models.JSONField(default=dict, blank=True)

    schema_version = models.IntegerField(default=SCHEMA_VERSION)

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"{self.nome} (Nível {self.nivel})"
