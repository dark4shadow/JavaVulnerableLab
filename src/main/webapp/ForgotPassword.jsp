
 <%@page import="org.cysecurity.cspf.jvl.model.DBConnect"%>
<%@page import="java.sql.PreparedStatement"%>
<%@page import="java.sql.ResultSet"%>
<%@page import="java.sql.Connection"%>
<%@ taglib prefix="fn" uri="http://java.sun.com/jsp/jstl/functions" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%!
    // Helper method to escape HTML to prevent XSS
    private String escapeHtml(String input) {
        if (input == null || input.isEmpty()) {
            return "";
        }
        // Properly escape all HTML special characters
        StringBuilder escaped = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '&':
                    escaped.append("&amp;");
                    break;
                case '<':
                    escaped.append("&lt;");
                    break;
                case '>':
                    escaped.append("&gt;");
                    break;
                case '"':
                    escaped.append("&quot;");
                    break;
                case '\'':
                    escaped.append("&#x27;");
                    break;
                case '/':
                    escaped.append("&#x2F;");
                    break;
                default:
                    escaped.append(c);
                    break;
            }
        }
        return escaped.toString();
    }
%>
<%@ include file="header.jsp" %>
     <script type="text/javascript">  
              $(document).ready(function(){  
                  $("#username").change(function(){  
                      var username = $(this).val();  
                      $.getJSON("UsernameCheck.do","username="+username,function(result)
                      {
                          if(result.available==1)
                          {
                          $("#status").html("<b style='color:green'>&#10004;</b>");
                           }
                           else
                           {
                               $("#status").html("<b style='color:red'>&#10006; username doesn't exist</b>");
                           }
                          
                      });
                  });  
              });  
            </script> 
            
Password Recovery: 
<form action="ForgotPassword.jsp" method="post">
<table> 
<tr><td>Username: </td><td><input type="text" name="username" id="username"/></td><td><span id="status"></span></td></tr>
<tr><td>What's Your Pet's name?: </td><td><input type="text" name="secret" /></td></tr>
<tr><td><input type="submit" name="GetPassword" value="GetPassword"/></td></tr>
</table>  
</form><br/>
 
<%
if (request.getParameter("secret") != null) {

    String username = request.getParameter("username").trim();
    String secret = request.getParameter("secret");

    //Edited: Використовуємо try-with-resources для автоматичного закриття ресурсів
    try (Connection con = new DBConnect().connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
         PreparedStatement stmt = con.prepareStatement(
                 "SELECT * FROM users WHERE username = ? AND secret = ?"
         )) {

        //Edited: Запобігання SQL Injection
        stmt.setString(1, username);
        stmt.setString(2, secret);

        // Edited: ResultSet теж закривається автоматично всередині try
        try (ResultSet rs = stmt.executeQuery()) {

            if (rs.next()) {
                // Escape HTML to prevent XSS attacks using custom sanitizer
                String username = rs.getString("username");
                String password = rs.getString("password");
                
                // Additional validation to ensure data is safe
                if (username == null) username = "";
                if (password == null) password = "";
                
                String safeUsername = escapeHtml(username);
                String safePassword = escapeHtml(password);
                
                out.print("Hello " + safeUsername +
                        ", <b class='success'> Your Password is: " + safePassword + "</b>");
            } else {
                out.print("<b class='fail'> Secret/Email is wrong</b>");
            }

        }

    } catch (Exception e) {
        e.printStackTrace();
        out.print("<b class='fail'>An error occurred</b>");
    }
}
                  
%>
               
  <%@ include file="footer.jsp" %>