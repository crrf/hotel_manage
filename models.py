from peewee import Model, CharField, BooleanField, SqliteDatabase, ForeignKeyField, IntegerField, DateField, FloatField

db = SqliteDatabase('database.db')

class BaseModel(Model):
    class Meta:
        database = db

class User(BaseModel):
    username = CharField(unique=True)
    password = CharField()
    is_admin = BooleanField(default=False)

class Reservacion(BaseModel):
    hotel = CharField()
    checkin = DateField()
    checkout = DateField()
    usuario = ForeignKeyField(User, backref='reservaciones')
    correo = CharField()
    metodo_pago = CharField()

class hoteles(BaseModel):
    Hotel = CharField()
    disponibilidad_habitaciones = IntegerField()
    precio = FloatField()

# Crear las tablas en la base de datos
db.connect()
db.create_tables([User, Reservacion,hoteles])