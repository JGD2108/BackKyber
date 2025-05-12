"""
Exportación de rutas de la API.

Este módulo exporta los routers para que puedan ser importados
fácilmente en el módulo principal.
"""
from app.api.routes.servers import router as servers_router
from app.api.routes.connection import router as connection_router
from app.api.routes.education import router as education_router

# Estos serán importados en main.py
servers = servers_router
connection = connection_router
education = education_router
