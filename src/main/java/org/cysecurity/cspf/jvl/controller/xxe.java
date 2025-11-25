package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;

// ===== ДОДАНО =====
import com.vulnlab.security.VaultUtil;
// ==================

/**
 *
 * @author breakthesec
 */
public class XPathQuery extends HttpServlet {

    /**
     * Escapes special characters in XPath expressions to prevent XPath injection
     * @param input the string to escape
     * @return the escaped string
     */
    private String escapeXPath(String input) {
        if (input == null) {
            return "";
        }
        // XPath 1.0 doesn't have escape sequences, so we need to handle quotes carefully
        // The safest approach is to use concat() for strings containing quotes
        if (input.contains("'")) {
            // Split by single quotes and concatenate with double quotes
            String[] parts = input.split("'", -1);
            StringBuilder sb = new StringBuilder("concat(");
            for (int i = 0; i < parts.length; i++) {
                if (i > 0) {
                    sb.append(",\"'\",");
                }
                sb.append("'").append(parts[i]).append("'");
            }
            sb.append(")");
            return sb.toString();
        }
        return input;
    }

    /**
     * Escapes HTML special characters to prevent XSS
     * @param input the string to escape
     * @return the escaped string
     */
    private String escapeHtml(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;")
                    .replace("/", "&#x2F;");
    }

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        try {
            String user = request.getParameter("username");
            String pass = request.getParameter("password");

            // Validate and sanitize inputs to prevent injection
            if (user == null || pass == null || user.isEmpty() || pass.isEmpty()) {
                response.sendRedirect(response.encodeURL(
                        "ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
                return;
            }
            
            // Strict validation: only allow alphanumeric characters and basic punctuation
            if (!user.matches("[a-zA-Z0-9@._-]+") || !pass.matches("[a-zA-Z0-9@._!#$%^&*()-]+")) {
                response.sendRedirect(response.encodeURL(
                        "ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
                return;
            }

            // XML Source:
            String XML_SOURCE = getServletContext().getRealPath("/WEB-INF/users.xml");

            // Parsing XML:
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);

            // ===== FIX: вимикаємо зовнішні сутності ===== 2 завдання друга вразливість
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setFeature("http://javax.xml.XMLConstants/feature/secure-processing", true);

            // Будуємо безпечний парсер
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document xDoc = builder.parse(XML_SOURCE);
            XPath xPath = XPathFactory.newInstance().newXPath();

            // ===== FIX: Properly escape XPath to prevent injection =====
            String escapedUser = escapeXPath(user);
            
            // ===== ЗМІНА: Беремо password тільки за username, без прямої перевірки ===== 3 завдання третявразливість
            String xExpression = "/users/user[username='" + escapedUser + "']/password";
            String vaultRef = xPath.compile(xExpression).evaluate(xDoc);

            // ===== ЗМІНА: Використовуємо Vault для отримання реального пароля ===== 3 завдання третя вразливість
            String vaultPass = VaultUtil.resolve(vaultRef);

            // ===== ЗМІНА: Перевірка пароля ===== 3 завдання третя вразливість
            if (vaultPass != null && pass.equals(vaultPass)) {
                // ===== ЗМІНА: Витягуємо ім'я користувача окремо ===== третє завдання третя вразливість
                String nameExpression = "/users/user[username='" + escapedUser + "']/name";
                String name = xPath.compile(nameExpression).evaluate(xDoc);
                
                // Sanitize name for session storage
                String safeName = escapeHtml(name);

                HttpSession session = request.getSession();
                session.setAttribute("isLoggedIn", "1");
                session.setAttribute("user", safeName);
                response.sendRedirect(response.encodeURL("ForwardMe?location=/index.jsp"));
            } else {
                response.sendRedirect(response.encodeURL(
                        "ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
            }

        } catch (Exception e) {
            out.print(e);
        } finally {
            out.close();
        }
    }

    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
