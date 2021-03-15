package com.dvctf.cryptex;

import a.b.c.e;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import b.a.a.a.a;
import com.dvctf.droid.R;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class LoginActivity extends e {
    public static byte[] p = {-114, 62, 98, 26, 54, -7, -59, -47, 55, 88, 18, -1, -99, 116, -51, 62};
    public static byte[] q = {-84, 25, 77, -101, -53, -124, -100, 61, 74, 102, 50, -11, -24, 62, -54, -71};
    public static byte[] r = {11, -35, 55, 10, 62, 79, 125, 62, -28, 115, 77, 4, 73, 0, 11, 121, -126, 85, -83, 109, 1, -98, 35, -68, -4, -122, 14, 110, -28, 111, 22, -125};

    public void a12dd3a7fd3203a452eb34d91a9be20569d5e337a3384347068895c07f3e0c5a(View view) {
        String str;
        byte[] bArr;
        TextView textView = (TextView) findViewById(R.id.pass);
        TextView textView2 = (TextView) findViewById(R.id.message);
        byte[] bytes = textView.getText().toString().getBytes();
        boolean z = false;
        try {
            byte[] bArr2 = p;
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr2, 0, bArr2.length, "AES");
            MessageDigest instance = MessageDigest.getInstance("SHA-256");
            instance.reset();
            byte[] digest = instance.digest(bytes);
            try {
                Cipher instance2 = Cipher.getInstance("AES/ECB/NoPadding");
                instance2.init(1, secretKeySpec);
                bArr = instance2.doFinal(digest);
            } catch (Exception e) {
                Log.w("Droid", "c6072170d758e5358d717360829bd1f9b1603b355b5f7fe375d1aabdca7a20de -> " + e.toString());
                bArr = q;
            }
            z = Arrays.equals(bArr, r);
        } catch (Exception e2) {
            StringBuilder e3 = a.e("fe6c188aec175974b53dedd6d27a79184f6032823302f2b907f54cdafa005cbc -> ");
            e3.append(e2.toString());
            Log.w("Droid", e3.toString());
        }
        if (z) {
            StringBuilder e4 = a.e("Congrats!! Validate the challenge with dvCTF{");
            e4.append(textView.getText().toString());
            e4.append("}");
            str = e4.toString();
        } else {
            str = "Nice try";
        }
        textView2.setText(str);
    }

    @Override // a.b.c.e, a.k.a.e, androidx.activity.ComponentActivity, a.h.b.g, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
    }
}