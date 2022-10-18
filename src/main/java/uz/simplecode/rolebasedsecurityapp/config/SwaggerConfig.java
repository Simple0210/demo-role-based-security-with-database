package uz.simplecode.rolebasedsecurityapp.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

  private static final String SCHEME_NAME = "basicAuth";
  private static final String SCHEME = "basic";

  @Bean
  public OpenAPI customOpenAPI() {
    return new OpenAPI()
            .addSecurityItem(new SecurityRequirement()
                    .addList(SCHEME_NAME))
            .components(new Components()
                    .addSecuritySchemes(SCHEME_NAME, new SecurityScheme()
                            .name(SCHEME_NAME)
                            .type(SecurityScheme.Type.HTTP)
                            .scheme(SCHEME)))

            .info(new Info()
                    .title("Security Demo API")
                    .version("0.0.1")
                    .contact(
                            new Contact()
                                    .email("a.abrorov@tengebank.uz")
                                    .name("Abrorov Alisher")
                    ));
  }
}
