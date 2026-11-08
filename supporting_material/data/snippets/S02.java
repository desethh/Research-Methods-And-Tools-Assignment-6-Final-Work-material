import javax.servlet.http.*;

public class RequestHandler extends HttpServlet
{
    public void handleRequest(HttpServletRequest request, HttpServletResponse response) throws Throwable
    {
        String data;

        data = "foo";

        if (data != null)
        {

            response.getWriter().println("<br>result - <img src=\"" + data + "\">");
        }

    }
}
