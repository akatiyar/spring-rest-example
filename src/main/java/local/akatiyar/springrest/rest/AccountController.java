/**
 * 
 */
package local.akatiyar.springrest.rest;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.data.rest.webmvc.config.RepositoryRestMvcConfiguration;
import org.springframework.stereotype.Controller;

/**
 * @author abhinav
 *
 */
@Configuration
@EnableJpaRepositories
@Import(RepositoryRestMvcConfiguration.class)
@Controller
public class AccountController {

}
