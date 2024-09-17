using Newtonsoft.Json;
using System.Net;
using System.Security.Cryptography;

string ip = "127.0.0.1";
int port = 1234;
int contador = 0;

List<Usuario> MisUsuarios = new List<Usuario>();
HttpListener listener = new HttpListener();

Console.SetWindowSize(100, 30);

string[] lines = {
            "/$$$$$$$$          /$$               /$$$$$$$                      /$$                    ",
            "|__  $$__/         | $$              | $$__  $$                    |__/                    ",
            "   | $$  /$$$$$$  /$$$$$$    /$$$$$$ | $$  \\ $$  /$$$$$$   /$$$$$$$ /$$  /$$$$$$  /$$$$$$$ ",
            "   | $$ |____  $$|_  $$_/   /$$__  $$| $$  | $$ /$$__  $$ /$$_____/| $$ /$$__  $$| $$__  $$",
            "   | $$  /$$$$$$$  | $$    | $$  \\ $$| $$  | $$| $$$$$$$$|  $$$$$$ | $$| $$  \\ $$| $$  \\ $$",
            "   | $$ /$$__  $$  | $$ /$$| $$  | $$| $$  | $$| $$_____/ \\____  $$| $$| $$  | $$| $$  | $$",
            "   | $$|  $$$$$$$  |  $$$$/|  $$$$$$/| $$$$$$$/|  $$$$$$$ /$$$$$$$/| $$|  $$$$$$$| $$  | $$",
            "   |__/ \\_______/   \\___/   \\______/ |_______/  \\_______/|_______/ |__/ \\____  $$|__/  |__/",
            "                                                                        /$$  \\ $$          ",
            "                                                                       |  $$$$$$/          ",
            "                                                                        \\______/           "
        };

foreach (string line in lines)
{
    Console.WriteLine(line);
    await Task.Delay(100); // 
}
Console.WriteLine("_______________________________________________________________________________________");


listener.Prefixes.Add($"http://{ip}:{port}/");
listener.Start();

Console.WriteLine($"\nServidor HTTP en ejecución en http://{ip}:{port}/\n");

while (true)
{
    var context = await listener.GetContextAsync();
    HandleRequest(context);
}

async void HandleRequest(HttpListenerContext context)
{
    var request = context.Request;
    var response = context.Response;

    Console.WriteLine($"\nPetición recibida: \nMetodo:{request.HttpMethod} - URL:{request.RawUrl}");

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
                        estado = usuarioDB.estado,
                        data = usuarioDB.data
                    },
                    token = usuarioDB.token
                };

                Console.WriteLine($"Se logio el usuario: {authData.username}\n");
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
            var usuarioExistente = MisUsuarios.FirstOrDefault(u => u.username == authData.username);

            if (usuarioExistente != null)
            {
                SendResponse("{\"msg\": \"Ya existe usuario con ese username\"}", 400, response);
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
                        estado = true,
                        data = new Dictionary<string, object>()
                    }
                };

                Console.WriteLine($"Se registro el usuario: {authData.username}\n");
                string contentResponse = JsonConvert.SerializeObject(RegisterResponse);
                SendResponse(contentResponse, 200, response);
            }
        }
    }

    //ACTUALIZAR USUARIOS
    else if (request.HttpMethod == "PATCH" && request.RawUrl == "/api/usuarios")
    {
        var reader = new StreamReader(request.InputStream, request.ContentEncoding);
        string requestBody = await reader.ReadToEndAsync();

        AuthData authData = JsonConvert.DeserializeObject<AuthData>(requestBody);
        Dictionary<string, object> updatedData = JsonConvert.DeserializeObject<Dictionary<string, object>>(requestBody);
        string token = request.Headers["x-token"];

        //Validaciones
        if (string.IsNullOrEmpty(token))
        {
            SendResponse("{\"msg\": \"No hay token en la petición\"}", 401, response);
        }
        else if (string.IsNullOrEmpty(authData.username))
        {
            SendResponse("{\"msg\": \"Debe enviar el usuario\",\n\"field\": \"username\"}", 400, response);
        }
        else
        {
            var usuarioDB = MisUsuarios.FirstOrDefault(u => u.username == authData.username);

            if (usuarioDB == null)
            {
                SendResponse($"{{\"msg\": \"No existe usuario con username {authData.username}\"}}", 400, response);
            }
            else if (usuarioDB.token != token)
            {
                SendResponse("{\"msg\": \"Token no valido \"}", 400, response);
            }
            else
            {
                updatedData.Remove("username");


                foreach (var kvp in updatedData)
                {
                    usuarioDB.data[kvp.Key] = kvp.Value;
                }

                var ActualizarResponse = new
                {
                    usuario = new
                    {
                        id = usuarioDB.id,
                        username = usuarioDB.username,
                        estado = usuarioDB.estado,
                        data = usuarioDB.data
                    }
                };

                Console.WriteLine($"Se actualizo la data para el usuario: {usuarioDB.username}\n");
                string contentResponse = JsonConvert.SerializeObject(ActualizarResponse);
                SendResponse(contentResponse, 200, response);
            }
        }
    }

    //LISTAR USUARIOS
    else if (request.HttpMethod == "GET" && request.RawUrl == "/api/usuarios")
    {
        string token = request.Headers["x-token"];

        //Validaciones
        if (string.IsNullOrEmpty(token))
        {
            SendResponse("{\"msg\": \"No hay token en la petición\"}", 401, response);
        }
        else
        {
            var usuarioDB = MisUsuarios.FirstOrDefault(u => u.token == token);

            if (usuarioDB == null)
            {
                SendResponse("{\"msg\": \"Token no valido\"}", 401, response);
            }
            else
            {
                var usuariosList = MisUsuarios.Select(u => new
                {
                    id = u.id,
                    username = u.username,
                    estado = u.estado,
                    data = u.data
                }).ToList();

                Console.WriteLine($"Se envio la lista de usuarios!\n");
                string contentResponse = JsonConvert.SerializeObject(new { usuarios = usuariosList });
                SendResponse(contentResponse, 200, response);
            }
        }
    }
    else
    {
        SendResponse("{\"msg\": \"Peticion no valida\"}", 400, response);
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
    public Dictionary<string, object> data { get; set; } = new Dictionary<string, object>();
}
