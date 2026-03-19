// ═══════════════════════════════════════════════════════════════
// TEST FILE: VulnJava.java
// EXPECTED: 7 findings (all True Positives)
// ═══════════════════════════════════════════════════════════════

import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;
import org.xml.sax.*;

public class VulnJava extends HttpServlet {

    // ── VULN 1: SQL Injection (CWE-89) ──────────────────────
    // EXPECTED: Critical — string concat in executeQuery
    protected void getUser(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String userId = request.getParameter("id");
        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "pass");
            Statement stmt = conn.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);
            PrintWriter out = response.getWriter();
            while (rs.next()) {
                out.println(rs.getString("name"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }


    // ── VULN 2: Command Injection (CWE-78) ──────────────────
    // EXPECTED: Critical — Runtime.exec with user input
    protected void pingHost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String host = request.getParameter("host");
        Runtime.getRuntime().exec("ping -c 4 " + host);
        response.getWriter().println("Ping sent to " + host);
    }


    // ── VULN 3: Insecure Deserialization (CWE-502) ──────────
    // EXPECTED: Critical — ObjectInputStream from user data
    protected void loadObject(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        try {
            Object obj = ois.readObject();
            response.getWriter().println("Loaded: " + obj.toString());
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }


    // ── VULN 4: XXE (CWE-611) ───────────────────────────────
    // EXPECTED: High — DocumentBuilderFactory without entity protection
    protected void parseXml(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();
            org.w3c.dom.Document doc = db.parse(request.getInputStream());
            response.getWriter().println("Parsed: " + doc.getDocumentElement().getTagName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    // ── VULN 5: XSS (CWE-79) ───────────────────────────────
    // EXPECTED: High — reflected user input in response
    protected void search(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String query = request.getParameter("q");
        PrintWriter out = response.getWriter();
        out.println("<html><body>");
        out.println("<h1>Results for: " + query + "</h1>");
        out.println("</body></html>");
    }


    // ── VULN 6: Hardcoded Credentials (CWE-798) ────────────
    // EXPECTED: High — database password in source
    private static final String DB_PASSWORD = "pr0duct10n_p@ssw0rd_2024!";
    private static final String API_SECRET = "sk-live-abcdef123456789ghijklmnop";


    // ── VULN 7: Path Traversal (CWE-22) ────────────────────
    // EXPECTED: High — user input in File constructor
    protected void downloadFile(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("file");
        File file = new File("/var/uploads/" + filename);
        FileInputStream fis = new FileInputStream(file);
        byte[] data = new byte[(int) file.length()];
        fis.read(data);
        fis.close();
        response.getOutputStream().write(data);
    }
}
