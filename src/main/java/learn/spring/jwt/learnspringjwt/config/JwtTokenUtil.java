package learn.spring.jwt.learnspringjwt.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtTokenUtil implements Serializable {

    public static final long JWT_TOKEN_VALIDITY= 5 * 60 *60;
    @Value("${jwt.secret}")
    private String secret;

    private Claims getAllClaimsFromToken(String token){
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
    public <T> T getClaimFromToken(String token, Function<Claims,T> claimsTFunction){
        final Claims claims=getAllClaimsFromToken(token);
        return claimsTFunction.apply(claims);
    }
    public String getUsernameFromToken(String token){
        return getClaimFromToken(token,Claims::getSubject);
    }
    public Date getExpiredDateFromToken(String token){
        return getClaimFromToken(token,Claims::getExpiration);
    }
    public Boolean isTokenExpired(String token){
        final Date expiration=getExpiredDateFromToken(token);
        return expiration.before(new Date());
    }
    private String genarateToken(Map<String,Object> claims, String subject){
        return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis()+JWT_TOKEN_VALIDITY*1000)).signWith(SignatureAlgorithm.HS512,secret).compact();
    }
    public String generateToken(UserDetails userDetails){
        Map<String,Object> claim=new HashMap<>();
        return genarateToken(claim,userDetails.getUsername());
    }
    public Boolean validateToken(String token, UserDetails userDetails){
        final String username=getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

}
