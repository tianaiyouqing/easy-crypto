package cloud.tianai.crypto.configutation;

import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class DMAutoConfiguration {

    @Bean
    @ConditionalOnWebApplication
    public DM dm() {
        return new DM();
    }
}
