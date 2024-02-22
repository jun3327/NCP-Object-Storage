package test.kim;

import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.FileEntity;
import org.apache.http.impl.client.HttpClientBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
@RequiredArgsConstructor
public class ImgService {

    private final UserRepository userRepository;
    private static final String REGION_NAME = "kr-standard";
    private static final String ENDPOINT = "https://kr.object.ncloudstorage.com";
    private static final String ACCESS_KEY = NcpObjectStorageConfig.accessKey;
    private static final String SECRET_KEY = NcpObjectStorageConfig.secretKey;

    private static final String CHARSET_NAME = "UTF-8";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String AWS_ALGORITHM = "AWS4-HMAC-SHA256";
    private static final String SERVICE_NAME = "s3";
    private static final String REQUEST_TYPE = "aws4_request";
    private static final String UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";
    private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyyMMdd");
    private static final SimpleDateFormat TIME_FORMATTER = new SimpleDateFormat("yyyyMMdd\'T\'HHmmss\'Z\'");

    private static byte[] sign(String stringData, byte[] key) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        byte[] data = stringData.getBytes(CHARSET_NAME);
        Mac e = Mac.getInstance(HMAC_ALGORITHM);
        e.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        return e.doFinal(data);
    }

    private static String hash(String text) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest e = MessageDigest.getInstance(HASH_ALGORITHM);
        e.update(text.getBytes(CHARSET_NAME));
        return Hex.encodeHexString(e.digest());
    }

    private static String getStandardizedQueryParameters(String queryString) throws UnsupportedEncodingException {
        TreeMap<String, String> sortedQueryParameters = new TreeMap<>();
        // sort by key name
        if (queryString != null && !queryString.isEmpty()) {
            String[] queryStringTokens = queryString.split("&");
            for (String field : queryStringTokens) {
                String[] fieldTokens = field.split("=");
                if (fieldTokens.length > 0) {
                    if (fieldTokens.length > 1) {
                        sortedQueryParameters.put(fieldTokens[0], fieldTokens[1]);
                    } else {
                        sortedQueryParameters.put(fieldTokens[0], "");
                    }
                }
            }
        }

        StringBuilder standardizedQueryParametersBuilder = new StringBuilder();
        int count = 0;
        for (String key : sortedQueryParameters.keySet()) {
            if (count > 0) {
                standardizedQueryParametersBuilder.append("&");
            }
            standardizedQueryParametersBuilder.append(key).append("=");

            if (sortedQueryParameters.get(key) != null && !sortedQueryParameters.get(key).isEmpty()) {
                standardizedQueryParametersBuilder.append(URLEncoder.encode(sortedQueryParameters.get(key), CHARSET_NAME));
            }

            count++;
        }
        return standardizedQueryParametersBuilder.toString();
    }

    private static TreeMap<String, String> getSortedHeaders(Header[] headers) {
        TreeMap<String, String> sortedHeaders = new TreeMap<>();
        // sort by header name
        for (Header header : headers) {
            sortedHeaders.put(header.getName(), header.getValue());
        }

        return sortedHeaders;
    }

    private static String getSignedHeaders(TreeMap<String, String> sortedHeaders) {
        StringBuilder signedHeadersBuilder = new StringBuilder();
        for (String headerName : sortedHeaders.keySet()) {
            signedHeadersBuilder.append(headerName.toLowerCase()).append(";");
        }
        String s = signedHeadersBuilder.toString();
        if (s.endsWith(";")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    private static String getStandardizedHeaders(TreeMap<String, String> sortedHeaders) {
        StringBuilder standardizedHeadersBuilder = new StringBuilder();
        for (String headerName : sortedHeaders.keySet()) {
            standardizedHeadersBuilder.append(headerName.toLowerCase()).append(":").append(sortedHeaders.get(headerName)).append("\n");
        }

        return standardizedHeadersBuilder.toString();
    }

    private static String getCanonicalRequest(HttpUriRequest request, String standardizedQueryParameters, String standardizedHeaders, String signedHeaders) {
        StringBuilder canonicalRequestBuilder = new StringBuilder().append(request.getMethod()).append("\n")
                .append(request.getURI().getPath()).append("\n")
                .append(standardizedQueryParameters).append("\n")
                .append(standardizedHeaders).append("\n")
                .append(signedHeaders).append("\n")
                .append(UNSIGNED_PAYLOAD);

        return canonicalRequestBuilder.toString();
    }

    private static String getScope(String datestamp, String regionName) {
        StringBuilder scopeBuilder = new StringBuilder().append(datestamp).append("/")
                .append(regionName).append("/")
                .append(SERVICE_NAME).append("/")
                .append(REQUEST_TYPE);
        return scopeBuilder.toString();
    }

    private static String getStringToSign(String timestamp, String scope, String canonicalRequest) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        StringBuilder stringToSignBuilder = new StringBuilder(AWS_ALGORITHM)
                .append("\n")
                .append(timestamp).append("\n")
                .append(scope).append("\n")
                .append(hash(canonicalRequest));

        return stringToSignBuilder.toString();
    }

    private static String getSignature(String secretKey, String datestamp, String regionName, String stringToSign) throws NoSuchAlgorithmException, UnsupportedEncodingException, InvalidKeyException {
        byte[] kSecret = ("AWS4" + secretKey).getBytes(CHARSET_NAME);
        byte[] kDate = sign(datestamp, kSecret);
        byte[] kRegion = sign(regionName, kDate);
        byte[] kService = sign(SERVICE_NAME, kRegion);
        byte[] signingKey = sign(REQUEST_TYPE, kService);

        return Hex.encodeHexString(sign(stringToSign, signingKey));
    }

    private static void putObject(String bucketName, String objectName,
                                  MultipartFile imgFile) throws IOException {
        HttpClient httpClient = HttpClientBuilder.create().build();

        //MultipartFile을 전송하기 위해 File로 변환 (MultipartFile -> File)
        //운영체제의 임시 폴더에 저장
        File file = new File(System.getProperty("java.io.tmpdir")+"/"+objectName);
        file.createNewFile();
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        fileOutputStream.write(imgFile.getBytes());
        fileOutputStream.close();

        HttpPut request = new HttpPut(ENDPOINT + "/" + bucketName + "/" + objectName);
        request.addHeader("Host", request.getURI().getHost());
        request.setEntity(new FileEntity(file));

        try {
            authorization(request, REGION_NAME, ACCESS_KEY, SECRET_KEY);
        } catch (Exception e) {

        }
        HttpResponse response = httpClient.execute(request);

        //로컬 임시폴더에 저장된 file 삭제
        file.delete();
        System.out.println("Response : " + response.getStatusLine());
    }

    private static void authorization(HttpUriRequest request, String regionName, String accessKey, String secretKey) throws Exception {
        Date now = new Date();
        DATE_FORMATTER.setTimeZone(TimeZone.getTimeZone("UTC"));
        TIME_FORMATTER.setTimeZone(TimeZone.getTimeZone("UTC"));
        String datestamp = DATE_FORMATTER.format(now);
        String timestamp = TIME_FORMATTER.format(now);

        request.addHeader("X-Amz-Date", timestamp);

        request.addHeader("X-Amz-Content-Sha256", UNSIGNED_PAYLOAD);

        String standardizedQueryParameters = getStandardizedQueryParameters(request.getURI().getQuery());

        TreeMap<String, String> sortedHeaders = getSortedHeaders(request.getAllHeaders());
        String signedHeaders = getSignedHeaders(sortedHeaders);
        String standardizedHeaders = getStandardizedHeaders(sortedHeaders);

        String canonicalRequest = getCanonicalRequest(request, standardizedQueryParameters, standardizedHeaders, signedHeaders);
        System.out.println("> canonicalRequest :");
        System.out.println(canonicalRequest);

        String scope = getScope(datestamp, regionName);

        String stringToSign = getStringToSign(timestamp, scope, canonicalRequest);
        System.out.println("> stringToSign :");
        System.out.println(stringToSign);

        String signature = getSignature(secretKey, datestamp, regionName, stringToSign);

        String authorization = getAuthorization(accessKey, scope, signedHeaders, signature);
        request.addHeader("Authorization", authorization);
    }

    private static String getAuthorization(String accessKey, String scope, String signedHeaders, String signature) {
        String signingCredentials = accessKey + "/" + scope;
        String credential = "Credential=" + signingCredentials;
        String signerHeaders = "SignedHeaders=" + signedHeaders;
        String signatureHeader = "Signature=" + signature;

        StringBuilder authHeaderBuilder = new StringBuilder().append(AWS_ALGORITHM).append(" ")
                .append(credential).append(", ")
                .append(signerHeaders).append(", ")
                .append(signatureHeader);

        return authHeaderBuilder.toString();
    }

    @Transactional
    public void save(MultipartFile imgFile, Long userId) {
        String bucketName = NcpObjectStorageConfig.bucketname;
        String objectName = UUID.randomUUID() + "_" + imgFile.getOriginalFilename();
        User user = userRepository.findById(userId).orElseThrow(RuntimeException::new);
        user.setProfileImgName(objectName);

        try {
            putObject(bucketName, objectName, imgFile);
        } catch(IOException e) {

        }
    }


    public byte[] send(Long userId) {

        User user = userRepository.findById(userId).orElseThrow(RuntimeException::new);
        String objectName = user.getProfileImgName();
        String bucketName = NcpObjectStorageConfig.bucketname;
        byte[] imgBytes = new byte[0];
        try {
            return imgBytes = getObject(bucketName, objectName);

        } catch (Exception e) {

        }
        return imgBytes;
    }

    private static byte[] getObject(String bucketName, String objectName) throws Exception {
        HttpClient httpClient = HttpClientBuilder.create().build();
        HttpGet request = new HttpGet(ENDPOINT + "/" + bucketName + "/" + objectName);
        request.addHeader("Host", request.getURI().getHost());

        authorization(request, REGION_NAME, ACCESS_KEY, SECRET_KEY);

        HttpResponse response = httpClient.execute(request);
        System.out.println("Response : " + response.getStatusLine());

        InputStream is = response.getEntity().getContent();
        //임시 폴더에 저장
//        File targetFile = new File(System.getProperty("java.io.tmpdir")+"/"+objectName);
//        OutputStream os = new FileOutputStream(targetFile);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buffer = new byte[8 * 1024];
        int bytesRead;
        while ((bytesRead = is.read(buffer)) != -1) {
            baos.write(buffer, 0, bytesRead);
        }
        byte[] result = baos.toByteArray();
        baos.close();
        is.close();
        return result;
    }
}
