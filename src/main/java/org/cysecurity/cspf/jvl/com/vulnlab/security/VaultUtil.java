package com.vulnlab.security;

import java.io.*;
import java.net.*;
import org.json.*;

public class VaultUtil {

    public static String resolve(String value) throws Exception {
        if (!value.startsWith("VAULT:")) {
            return value;
        }

        String path = value.substring(6);

        URL url = new URL("http://127.0.0.1:8200/v1/secret/data/" + path);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");
        con.setRequestProperty("X-Vault-Token", System.getenv("VAULT_TOKEN"));

        BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
        StringBuilder resp = new StringBuilder();
        String line;

        while ((line = in.readLine()) != null) {
            resp.append(line);
        }
        in.close();

        JSONObject json = new JSONObject(resp.toString());
        return json.getJSONObject("data").getJSONObject("data").getString("password");
    }
}

// це все новий файл для vault 3 завдання 3-я вразливість

