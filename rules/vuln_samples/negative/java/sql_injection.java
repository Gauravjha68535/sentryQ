import java.sql.*;
import javax.servlet.http.*;

public class SafeServlet extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        String id = request.getParameter("id");
        
        // Safe: PreparedStatement
        PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
        ps.setString(1, id);
        ps.executeQuery();
    }
}
