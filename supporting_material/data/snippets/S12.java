import javax.servlet.http.*;
import java.net.URLEncoder;

public class RequestHandler extends HttpServlet
{
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        data = request.getParameter("name");

        if (data != null)
        {

            response.setHeader("Location", "/author.jsp?lang=" + data);
        }

    }
}
