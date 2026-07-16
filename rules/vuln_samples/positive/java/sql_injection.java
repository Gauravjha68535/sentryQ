import java.sql.*;
import javax.servlet.http.*;

public class UserServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        String id = request.getParameter("id");
        
        // Unsafe: concatenation in executeQuery
        Statement stmt = conn.createStatement();
        stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
        
        // Unsafe: string concat
        conn.createStatement().execute("DELETE FROM sessions WHERE user_id = " + id);
    }
}
