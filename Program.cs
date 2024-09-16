using Newtonsoft.Json;
using System.Net;
using System.Security.Cryptography;

string ip = "127.0.0.1";
int port = 1234;
int contador = 0;

List<Usuario> MisUsuarios = new List<Usuario>();

HttpListener listener = new HttpListener();
listener.Prefixes.Add($"http://{ip}:{port}/");
listener.Start();

Console.WriteLine($"Servidor HTTP en ejecución en http://{ip}:{port}/");

while (true)
{
    var context = await listener.GetContextAsync();
    HandleRequest(context);
}

async void HandleRequest(HttpListenerContext context)
{
    var request = context.Request;
    var response = context.Response;

    Console.WriteLine($"Petición recibida: \nMetodo:{request.HttpMethod} - URL:{request.RawUrl}\n");

    // LOGIN
    if (request.HttpMethod == "POST" && request.RawUrl == "/api/auth/login")
    {
        var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        string requestBody = await reader.ReadToEndAsync();

        AuthData authData = JsonConvert.DeserializeObject<AuthData>(requestBody);

        // VALIDACIONES
        if (string.IsNullOrEmpty(authData.username))
        {
            SendResponse("{\"msg\": \"debe enviar el campo username en la petición\",\"field\": \"username\"}", 400, response);
        }
        else if (string.IsNullOrEmpty(authData.password))
        {
            SendResponse("{\"msg\": \"debe enviar el campo password en la petición\",\"field\": \"password\"}", 400, response);
        }
        else
        {
            var usuarioDB = MisUsuarios.FirstOrDefault(u => u.username == authData.username);

            if (usuarioDB == null || usuarioDB.password != authData.password)
            {
                SendResponse("{\"msg\": \"usuario o contraseña no son correctos\"}", 400, response);
            }
            else
            {
                var loginResponse = new
                {
                    usuario = new
                    {
                        id = usuarioDB.id,
                        username = usuarioDB.username,
                        estado = usuarioDB.estado
                    },
                    token = usuarioDB.token
                };

                string contentResponse = JsonConvert.SerializeObject(loginResponse);
                SendResponse(contentResponse, 200, response);
            }
        }
    }

    // REGISTRO
    else if (request.HttpMethod == "POST" && request.RawUrl == "/api/usuarios")
    {
        var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        string requestBody = await reader.ReadToEndAsync();

        AuthData authData = JsonConvert.DeserializeObject<AuthData>(requestBody);

        // VALIDACIONES
        if (string.IsNullOrEmpty(authData.username))
        {
            SendResponse("{\"msg\": \"Debe enviar el usuario\"}", 400, response);
        }
        else if (string.IsNullOrEmpty(authData.password))
        {
            SendResponse("{\"msg\": \"Debe enviar el password\"}", 400, response);
        }
        else
        {
            string token = GenerarTokenAleatorio();
            contador += 1;

            Usuario nuevoUsuario = new Usuario()
            {
                id = contador,
                username = authData.username,
                password = authData.password,
                estado = true,
                token = token
            };

            MisUsuarios.Add(nuevoUsuario);

            var RegisterResponse = new
            {
                usuario = new
                {
                    id = contador,
                    username = authData.username,
                    estado = true
                }
            };

            string contentResponse = JsonConvert.SerializeObject(RegisterResponse);
            SendResponse(contentResponse, 200, response);
        }
    }

    //ACTUALIZAR USUARIOS
    else if (request.HttpMethod == "PATCH" && request.RawUrl == "/api/usuarios")
    {
        string token = request.Headers["x-token"];

        if (string.IsNullOrEmpty(token))
        {
            SendResponse("{\"msg\": \"Token requerido\"}", 400, response);
        }
        else
        {
            // Lógica para actualizar usuarios
        }
    }
    // Listar usuarios
    else
    {
        SendResponse("", 404, response);
    }
}

async void SendResponse(string content, int statusCode, HttpListenerResponse response)
{
    int contentLength = System.Text.Encoding.UTF8.GetByteCount(content);
    response.ContentLength64 = contentLength;
    response.ContentType = "application/json";
    response.StatusCode = statusCode;

    var output = response.OutputStream;
    var buffer = System.Text.Encoding.UTF8.GetBytes(content);

    await output.WriteAsync(buffer, 0, buffer.Length);
    output.Close();
}

string GenerarTokenAleatorio()
{
    var randomBytes = new byte[32];
    using (var rng = RandomNumberGenerator.Create())
    {
        rng.GetBytes(randomBytes);
    }

    return Convert.ToBase64String(randomBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

class AuthResponse
{
    public Usuario usuario { get; set; }
    public string token { get; set; }

    public AuthResponse(Usuario usuarioDB)
    {
        usuario = new Usuario
        {
            username = usuarioDB.username
        };
        token = usuarioDB.token;
    }
}

class RegistroResponse
{
    public Usuario usuario { get; set; }

    public RegistroResponse(Usuario usuarioDB)
    {
        usuario = new Usuario
        {
            username = usuarioDB.username,
            password = usuarioDB.password
            // No se incluye el token aquí
        };
    }
}

class AuthData
{
    public string username { get; set; }
    public string password { get; set; }
}

class Usuario
{
    public int id { get; set; }
    public string username { get; set; }
    public string password { get; set; }
    public bool estado { get; set; }
    public string token { get; set; }
}
