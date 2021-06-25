package cryptopals.web.config;

import cryptopals.web.config.properties.LeakingProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableConfigurationProperties(LeakingProperties.class)
public class LeakingConfig {
}
