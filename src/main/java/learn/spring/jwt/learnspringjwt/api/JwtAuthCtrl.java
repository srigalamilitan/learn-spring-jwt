package learn.spring.jwt.learnspringjwt.api;

import learn.spring.jwt.learnspringjwt.api.dto.LoginDto;
import learn.spring.jwt.learnspringjwt.api.dto.LoginResponse;
import learn.spring.jwt.learnspringjwt.config.JwtTokenUtil;
import learn.spring.jwt.learnspringjwt.service.JwtUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@CrossOrigin
public class JwtAuthCtrl {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenUtil jwtTokenUtil;
    @Autowired
    private JwtUserService jwtUserService;

    @PostMapping("/auth")
    public ResponseEntity<?> createAuthToken(@RequestBody LoginDto loginDto) throws Exception{
        authenticate(loginDto.getUsername(),loginDto.getPassword());
        final UserDetails userDetails=jwtUserService.loadUserByUsername(loginDto.getUsername());
        final String token=jwtTokenUtil.generateToken(userDetails);
        return ResponseEntity.ok(new LoginResponse(token));
    }

    private void authenticate(String username,String password) throws Exception{
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username,password));
        }catch (DisabledException e){
            throw new Exception("USER_DISABLED",e);
        }catch (BadCredentialsException ee){
            throw new Exception("INVALID_CREDENTIAL",ee);
        }
    }
}
