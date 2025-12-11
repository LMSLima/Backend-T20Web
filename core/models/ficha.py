from django.db import models

class Ficha(models.Model):
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    owner = models.ForeignKey(
        "User", on_delete=models.CASCADE, related_name="fichas"
    )

    def __str__(self):
        return self.title
