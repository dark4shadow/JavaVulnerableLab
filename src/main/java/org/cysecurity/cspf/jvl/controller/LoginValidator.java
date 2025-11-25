/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package org.cysecurity.cspf.jvl.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.cysecurity.cspf.jvl.model.DBConnect;
 
 

/**
 *
 * @author breakthesec
 */
public class LoginValidator extends HttpServlet {

    /**
     * Sanitizes cookie values to prevent CRLF injection
     */
    private String sanitizeCookieValue(String value) {
        if (value == null) return "";
        // Remove all newline and carriage return characters
        return value.replaceAll("[\\r\\n]", "");
    }

    /**
     * Escapes HTML special characters to prevent XSS
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

    /**
     * Processes requests for both HTTP <code>GET</code> and <code>POST</code>
     * methods.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        
       String user = request.getParameter("username");
       String pass = request.getParameter("password");
       
       // Validate input
       if (user == null || pass == null) {
           response.sendRedirect("ForwardMe?location=/login.jsp?err=Invalid Username or Password");
           return;
       }
       
       user = user.trim();
       pass = pass.trim();
       
       // Use try-with-resources for automatic resource management
       try (Connection con = new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"))) {
           if (con != null && !con.isClosed()) {
               // Use PreparedStatement to prevent SQL injection
               String query = "SELECT * FROM users WHERE username=? AND password=?";
               try (PreparedStatement pstmt = con.prepareStatement(query)) {
                   pstmt.setString(1, user);
                   pstmt.setString(2, pass);
                   
                   try (ResultSet rs = pstmt.executeQuery()) {
                       if (rs != null && rs.next()) {
                           HttpSession session = request.getSession();
                           session.setAttribute("isLoggedIn", "1");
                           
                           // Sanitize data before storing in session
                           String userId = escapeHtml(rs.getString("id"));
                           String username = escapeHtml(rs.getString("username"));
                           String avatar = escapeHtml(rs.getString("avatar"));
                           
                           session.setAttribute("userid", userId);
                           session.setAttribute("user", username);
                           session.setAttribute("avatar", avatar);
                           
                           // Set secure cookie with HttpOnly and Secure flags
                           Cookie privilege = new Cookie("privilege", "user");
                           privilege.setHttpOnly(true);
                           privilege.setSecure(true);
                           privilege.setPath("/");
                           response.addCookie(privilege);
                           
                           if (request.getParameter("RememberMe") != null) {
                               // Sanitize cookie values to prevent CRLF injection
                               String sanitizedUser = sanitizeCookieValue(user);
                               String sanitizedPass = sanitizeCookieValue(pass);
                               
                               Cookie usernameCookie = new Cookie("username", sanitizedUser);
                               usernameCookie.setHttpOnly(true);
                               usernameCookie.setSecure(true);
                               usernameCookie.setPath("/");
                               usernameCookie.setMaxAge(60 * 60 * 24 * 7); // 7 days
                               
                               Cookie passwordCookie = new Cookie("password", sanitizedPass);
                               passwordCookie.setHttpOnly(true);
                               passwordCookie.setSecure(true);
                               passwordCookie.setPath("/");
                               passwordCookie.setMaxAge(60 * 60 * 24 * 7); // 7 days
                               
                               response.addCookie(usernameCookie);
                               response.addCookie(passwordCookie);
                           }
                           response.sendRedirect(response.encodeURL("ForwardMe?location=/index.jsp"));
                       } else {
                           response.sendRedirect("ForwardMe?location=/login.jsp?err=Invalid Username or Password");
                       }
                   }
               }
           }
       } catch (Exception ex) {
           ex.printStackTrace();
           response.sendRedirect("login.jsp?err=something went wrong");
       }
    }
    // <editor-fold defaultstate="collapsed" desc="HttpServlet methods. Click on the + sign on the left to edit the code.">
    /**
     * Handles the HTTP <code>GET</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Handles the HTTP <code>POST</code> method.
     *
     * @param request servlet request
     * @param response servlet response
     * @throws ServletException if a servlet-specific error occurs
     * @throws IOException if an I/O error occurs
     */
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    /**
     * Returns a short description of the servlet.
     *
     * @return a String containing servlet description
     */
    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
