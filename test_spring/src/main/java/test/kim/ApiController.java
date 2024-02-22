package test.kim;

import lombok.RequiredArgsConstructor;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.Base64;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class ApiController {

    private final ImgService imgService;

    @GetMapping("/hello")
    public String hello() {
        return "배포 성공 !";
    }

    @PostMapping("/profileImg")
    public void saveImg(@RequestParam(value = "imgFile") MultipartFile imgFile,
                        @RequestParam(value = "userId") Long userId) {
        imgService.save(imgFile, userId);
    }

    @GetMapping("/profileImg/{id}")
    public byte[] sendImg(@PathVariable("id") Long userId) {
       return imgService.send(userId);
    }
}
