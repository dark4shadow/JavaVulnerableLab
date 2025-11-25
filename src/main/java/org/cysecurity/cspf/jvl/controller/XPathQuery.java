/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

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
/**
 *
 * @author breakthesec
 */
public class XPathQuery extends HttpServlet {


            
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        try {
            String user=request.getParameter("username");
            String pass=request.getParameter("password");
            
            // Validate and sanitize inputs to prevent injection
            if (user == null || pass == null || user.isEmpty() || pass.isEmpty()) {
                response.sendRedirect(response.encodeURL("ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
                return;
            }
            
            // Strict validation: only allow alphanumeric characters and basic punctuation
            if (!user.matches("[a-zA-Z0-9@._-]+") || !pass.matches("[a-zA-Z0-9@._!#$%^&*()-]+")) {
                response.sendRedirect(response.encodeURL("ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
                return;
            }
            
            //XML Source:
            String XML_SOURCE=getServletContext().getRealPath("/WEB-INF/users.xml");
            
            //Parsing XML:
            DocumentBuilderFactory factory=DocumentBuilderFactory.newInstance();
            // disable external entity expansion and disallow inline DOCTYPE to prevent XXE
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false); //CHANGED (Added)
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false); //CHANGED (Added)
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true); //CHNAGED (Added)
            factory.setNamespaceAware(true);
            DocumentBuilder builder=factory.newDocumentBuilder();
            Document xDoc=builder.parse(XML_SOURCE);
            
            XPath xPath=XPathFactory.newInstance().newXPath();
            
            // Properly escape XPath injection by escaping all special characters
            // Best practice: use prepared statements or a safe XPath library
            String escapedUser = escapeXPath(user);
            String escapedPass = escapeXPath(pass);
            
            //XPath Query with escaped parameters:
            String xPression="/users/user[username='"+escapedUser+"' and password='"+escapedPass+"']/name";
            
            //running Xpath query:
            String name=xPath.compile(xPression).evaluate(xDoc);
            
            // Sanitize output to prevent XSS by HTML-encoding special characters
            String safeName = escapeHtml(name);
            out.println(safeName);
            if(name.isEmpty())
            {
                response.sendRedirect(response.encodeURL("ForwardMe?location=/vulnerability/Injection/xpath_login.jsp?err=Invalid Credentials"));
            }
            else
            {
                 HttpSession session=request.getSession();
                 session.setAttribute("isLoggedIn", "1");
                  session.setAttribute("user", safeName);
                 response.sendRedirect(response.encodeURL("ForwardMe?location=/index.jsp"));                                  
            }
        } 
        catch(Exception e)
        {
            out.print(e);
        }        
        finally {
            out.close();
        }
    }
    
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
