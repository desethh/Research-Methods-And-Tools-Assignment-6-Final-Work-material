import javax.servlet.http.*;

public class RequestHandler extends HttpServlet
{
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        data = request.getParameter("name");

        String osCommand;
        if(System.getProperty("os.name").toLowerCase().indexOf("win") >= 0)
        {

            osCommand = "c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir ";
        }
        else
        {

            osCommand = "/bin/ls ";
        }

        Process process = Runtime.getRuntime().exec(osCommand + data);
        process.waitFor();

    }
}
