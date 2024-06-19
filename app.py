from flask import Flask, render_template, redirect, url_for, request, flash, session
from peewee import SqliteDatabase
from models import User , Reservacion , hoteles
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from functools import wraps  
from flask_login import current_user, login_manager , login_required, logout_user, login_user


logged_user = 0
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
Bootstrap(app)

db = SqliteDatabase('users.db')

@app.before_request
def before_request():
    db.connect()

@app.after_request
def after_request(response):
    db.close()
    return response

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = User.get_by_id(session['user_id'])
        if not user.is_admin:
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        is_admin = 'is_admin' in request.form
        User.create(username=username, password=password, is_admin=is_admin)
        flash('User registered successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            user = User.get(User.username == username)
            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                session['is_admin'] = user.is_admin
                if user.is_admin:
                    return redirect(url_for('admin'))
                else:
                    return redirect(url_for('index'))
            else:
                flash('Incorrect password', 'danger')
        except User.DoesNotExist:
            flash('Username does not exist', 'danger')
    return render_template('login.html')

@app.route('/')
def index():
    return render_template('welcome.html')

@app.route('/admin')
@admin_required
def admin():
    users = User.select()
    return render_template('admin.html', users=users)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    user = User.get_by_id(user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        if request.form['password']:
            user.password = generate_password_hash(request.form['password'])
        user.save()
        flash('User updated successfully', 'success')
        return redirect(url_for('admin'))
    return render_template('edit_user.html', user=user)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.get_by_id(user_id)
    user.delete_instance()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))


@app.route('/reserve_hotel', methods=['GET', 'POST'])
@login_required
def reserve_hotel():
    hoteles_list = hoteles.select()
    
    if request.method == 'POST':
        hotel_id = request.form['hotel']
        checkin_date = request.form['checkin']
        checkout_date = request.form['checkout']
        usuario_id = User.get_by_id(session['user_id'])  # Usar el usuario actualmente logueado
        correo = request.form['correo']
        metodo_pago = request.form['metodo_pago']

        try:
            nueva_reservacion = Reservacion.create(
                hotel=hotel_id,  # Guardar el ID del hotel en lugar del nombre
                checkin=checkin_date,
                checkout=checkout_date,
                usuario_id=usuario_id,
                correo=correo,
                metodo_pago=metodo_pago
            )
            flash('Reservación realizada correctamente', 'success')
        except Exception as e:
            flash(f'Error al realizar la reservación: {str(e)}', 'danger')

        return redirect(url_for('index'))

    return render_template('reserve_hotel.html', hoteles=hoteles_list)

@app.route('/ver_reservaciones')
@login_required
def ver_reservaciones():
    user = User.get_by_id(session['user_id'])
    reservaciones = Reservacion.select().where(Reservacion.usuario_id == user)

    return render_template('ver_reservaciones.html', reservaciones=reservaciones)


@app.route('/admin/reservaciones')
@admin_required
def admin_reservaciones():
    reservaciones = Reservacion.select()
    return render_template('admin_reservaciones.html', reservaciones=reservaciones)

@app.route('/admin/editar_reservacion/<int:reservacion_id>', methods=['GET', 'POST'])
@admin_required
def admin_editar_reservacion(reservacion_id):
    reservacion = Reservacion.get_or_none(Reservacion.id == reservacion_id)
    if request.method == 'POST':
        reservacion.hotel = request.form['hotel']
        reservacion.checkin = request.form['checkin']
        reservacion.checkout = request.form['checkout']
        reservacion.correo = request.form['correo']
        reservacion.metodo_pago = request.form['metodo_pago']
        reservacion.save()
        flash('Reservación actualizada correctamente', 'success')
        return redirect(url_for('admin_reservaciones'))
    return render_template('admin_editar_reservacion.html', reservacion=reservacion)

@app.route('/admin/borrar_reservacion/<int:reservacion_id>', methods=['POST'])
@admin_required
def admin_borrar_reservacion(reservacion_id):
    reservacion = Reservacion.get_or_none(Reservacion.id == reservacion_id)
    if reservacion:
        reservacion.delete_instance()
        flash('Reservación borrada correctamente', 'success')
    else:
        flash('Reservación no encontrada', 'danger')
    return redirect(url_for('admin_reservaciones'))


@app.route('/add_hotel', methods=['GET', 'POST'])
@admin_required
def add_hotel():
    if request.method == 'POST':
        hotel = request.form['hotel']
        disponibilidad = int(request.form['disponibilidad'])
        precio = float(request.form['precio'])

        try:
            nuevo_hotel = hoteles.create(
                Hotel=hotel, disponibilidad_habitaciones=disponibilidad, precio=precio
            )
            flash('Hotel agregado correctamente', 'success')
        except Exception as e:
            flash(f'Error al agregar hotel: {str(e)}', 'danger')

        return redirect(url_for('admin'))

    return render_template('add_hotel.html')


@app.route('/admin_hoteles')
@admin_required
def admin_hoteles():
    hoteles_list = hoteles.select()
    return render_template('admin_hoteles.html', hoteles=hoteles_list)

@app.route('/edit_hotel/<int:hotel_id>', methods=['GET', 'POST'])
@admin_required
def edit_hotel(hotel_id):
    hotel = hoteles.get_by_id(hotel_id)
    if request.method == 'POST':
        hotel.Hotel = request.form['hotel']
        hotel.disponibilidad_habitaciones = int(request.form['disponibilidad'])
        hotel.precio = float(request.form['precio'])
        hotel.save()
        flash('Hotel actualizado correctamente', 'success')
        return redirect(url_for('admin_hoteles'))
    return render_template('edit_hotel.html', hotel=hotel)

@app.route('/delete_hotel/<int:hotel_id>', methods=['POST'])
@admin_required
def delete_hotel(hotel_id):
    hotel = hoteles.get_by_id(hotel_id)
    hotel.delete_instance()
    flash('Hotel eliminado correctamente', 'success')
    return redirect(url_for('admin_hoteles'))

@app.route('/ver_hoteles')
@admin_required
def ver_hoteles():
    hoteles_list = hoteles.select()
    return render_template('ver_hoteles.html', hoteles=hoteles_list)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
 