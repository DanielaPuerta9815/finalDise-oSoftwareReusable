from abc import ABC, abstractmethod

# -----------------------------
# Clase Usuario
# -----------------------------
class Usuario:
    def __init__(self, usuario, contraseña, rol):
        self.usuario = usuario
        self.contraseña = contraseña
        self.rol = rol

    def crearOrden(self, solicitud):
        return Orden(1, solicitud['tipo'], 'pendiente', self)

    def iniciarSesion(self, usuario, contraseña):
        return self.usuario == usuario and self.contraseña == contraseña


# -----------------------------
# Clase Orden
# -----------------------------
class Orden:
    def __init__(self, id, tipo, estado, usuario):
        self.id = id
        self.tipo = tipo
        self.estado = estado
        self.usuario = usuario

    def confirmar(self):
        self.estado = 'confirmada'
        return True


# -----------------------------
# Interfaz Validacion
# -----------------------------
class Validacion(ABC):
    def __init__(self):
        self.siguiente = None

    def setSiguiente(self, validacion):
        self.siguiente = validacion

    @abstractmethod
    def realizarVerificacion(self, solicitud):
        pass


# -----------------------------
# Validación 1: Se requiere validar la Autenticación
# -----------------------------
class Autenticacion(Validacion):
    def __init__(self, usuarios):
        super().__init__()
        self.usuarios = usuarios

    def realizarVerificacion(self, solicitud):
        usuario = solicitud.get("usuario")
        contraseña = solicitud.get("contraseña")
        for user in self.usuarios:
            if user.iniciarSesion(usuario, contraseña):
                print(f"[Autenticación] Usuario '{usuario}' autenticado.")
                solicitud["usuario_obj"] = user
                return self.siguiente.realizarVerificacion(solicitud) if self.siguiente else True
        print("[Autenticación] Fallida.")
        return False


# -----------------------------
# Validación 2: Paso seguido se pide Sanear los datos
# -----------------------------
class Sanear(Validacion):
    def __init__(self):
        super().__init__()
        self.reglas = ["<script>", ";", "--"]

    def realizarVerificacion(self, solicitud):
        for regla in self.reglas:
            for valor in solicitud.values():
                if isinstance(valor, str) and regla in valor:
                    print("[Sanear] Solicitud contiene datos no seguros.")
                    return False
        print("[Sanear] Datos limpios.")
        return self.siguiente.realizarVerificacion(solicitud) if self.siguiente else True


# -----------------------------
# Validación 3: Se debe contar los intentos fallido e implementar un Filtro IP y bloquear IPs
# -----------------------------
class FiltroIp(Validacion):
    def __init__(self):
        super().__init__()
        self.intentosFallidos = 0
        self.ipBloqueadas = []

    def realizarVerificacion(self, solicitud):
        ip = solicitud.get("ip")
        if ip in self.ipBloqueadas:
            print(f"[Filtro IP] IP {ip} está bloqueada.")
            return False

        if self.siguiente:
            resultado = self.siguiente.realizarVerificacion(solicitud)
            if not resultado:
                self.intentosFallidos += 1
                if self.intentosFallidos >= 3:
                    self.ipBloqueadas.append(ip)
                    print(f"[Filtro IP] IP {ip} bloqueada por múltiples fallos.")
            return resultado
        return True


# -----------------------------
# Validación 4: Se debe guardar en Cache para permitir que e sistema sea mas rapido en la entrega de la respuesta
# -----------------------------
class GuardaCache(Validacion):
    def __init__(self):
        super().__init__()
        self.cache = {}

    def realizarVerificacion(self, solicitud):
        clave = str(solicitud)
        if clave in self.cache:
            print("[Cache] Resultado encontrado en cache.")
            return self.cache[clave]

        print("[Cache] No hay resultado cacheado.")
        resultado = self.siguiente.realizarVerificacion(solicitud) if self.siguiente else True
        self.cache[clave] = resultado
        return resultado


# -----------------------------
# Clase Sistema orquestador de las validaciones, la gestion de ordenes y el inicio de sesion correcto, ademas de contar con usuarios
# -----------------------------
class Sistema:
    def __init__(self, validacion):
        self.validacion = validacion
        self.ordenes = []

    def realizarVerificacion(self, solicitud):
        return self.validacion.realizarVerificacion(solicitud)

    def registrarOrden(self, solicitud):
        usuario = solicitud.get("usuario_obj")
        orden = Orden(len(self.ordenes)+1, solicitud["tipo"], "pendiente", usuario)
        self.ordenes.append(orden)
        print("[Sistema] Orden registrada.")
        return orden

    def autenticarUsuario(self, solicitud):
        return self.realizarVerificacion(solicitud)


# -----------------------------
# Ejecución de pruebas
# -----------------------------
if __name__ == "__main__":
    # Usuarios registrados
    usuarios = [
        Usuario("admin", "admin123", "admin"),
        Usuario("user1", "pass1", "cliente")
    ]

    # Crear validaciones (orden correcto) seteamos el orden que nos solicitaron en el enunciado
    autenticacion = Autenticacion(usuarios)  # 1
    sanear = Sanear()                        # 2
    filtro_ip = FiltroIp()                   # 3
    guarda_cache = GuardaCache()            # 4

    # Enlazar la cadena, damos valor al metodo definido en la interfaz
    autenticacion.setSiguiente(sanear)
    sanear.setSiguiente(filtro_ip)
    filtro_ip.setSiguiente(guarda_cache)

    # Crear sistema inicializamos el sistema con la primera validacion
    sistema = Sistema(autenticacion)

    # IP a bloquear indicamos la ip que se va a bloquear
    ip_bloqueada = "192.168.1.100"

    # Solicitudes de prueba  - definimos los casos de pruebas
    solicitudes = [
        {
            "nombre": "1. Fallo de autenticación",
            "data": {
                "usuario": "user1",
                "contraseña": "incorrecta",
                "tipo": "compra",
                "ip": "192.168.1.2"
            }
        },
        {
            "nombre": "2. Fallo por saneamiento",
            "data": {
                "usuario": "admin",
                "contraseña": "admin123",
                "tipo": "compra<script>",
                "ip": "192.168.1.3"
            }
        },
        {
            "nombre": "3a. Filtro IP - intento 1 (fallo)",
            "data": {
                "usuario": "user1",
                "contraseña": "incorrecta",
                "tipo": "compra",
                "ip": ip_bloqueada
            }
        },
        {
            "nombre": "3b. Filtro IP - intento 2 (fallo)",
            "data": {
                "usuario": "user1",
                "contraseña": "incorrecta",
                "tipo": "compra",
                "ip": ip_bloqueada
            }
        },
        {
            "nombre": "3c. Filtro IP - intento 3 (bloqueo)",
            "data": {
                "usuario": "user1",
                "contraseña": "incorrecta",
                "tipo": "compra",
                "ip": ip_bloqueada
            }
        },
        {
            "nombre": "3d. Filtro IP - acceso luego de bloqueo (fallo aunque datos válidos)",
            "data": {
                "usuario": "user1",
                "contraseña": "pass1",
                "tipo": "compra",
                "ip": ip_bloqueada
            }
        },
        {
            "nombre": "4. Repetida con fallo (verifica cache con resultado fallido)",
            "data": {
                "usuario": "admin",
                "contraseña": "admin123",
                "tipo": "compra<script>",
                "ip": "192.168.1.3"
            }
        },
        {
            "nombre": "5. Solicitud exitosa",
            "data": {
                "usuario": "user1",
                "contraseña": "pass1",
                "tipo": "venta",
                "ip": "192.168.1.4"
            }
        },
        {
            "nombre": "6. Solicitud repetida válida (verifica uso de cache)",
            "data": {
                "usuario": "user1",
                "contraseña": "pass1",
                "tipo": "venta",
                "ip": "192.168.1.4"
            }
        }
    ]

    # Ejecutar solicitudes
    for solicitud in solicitudes:
        print(f"\n--- {solicitud['nombre']} ---")
        datos = solicitud["data"]
        if sistema.autenticarUsuario(datos):
            orden = sistema.registrarOrden(datos)
            print(f"[Cliente] Orden creada: ID={orden.id}, Estado={orden.estado}")
        else:
            print("[Cliente] No se pudo autenticar o validar la solicitud.")
