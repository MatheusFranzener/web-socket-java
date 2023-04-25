package br.senai.sc.editoralivros.util;

import br.senai.sc.editoralivros.model.dto.LivroDTOCadastro;
import br.senai.sc.editoralivros.model.entity.Arquivo;
import br.senai.sc.editoralivros.model.entity.Livro;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.web.multipart.MultipartFile;

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class LivroUtil {
    private ObjectMapper objectMapper = new ObjectMapper();


    public Livro convertJsonToModel(String livroJson) {
        LivroDTOCadastro livroDTOCadastro = convertJsonToDto(livroJson);
        return convertDtoToModel(livroDTOCadastro);
    }

    private LivroDTOCadastro convertJsonToDto(String livroJson){
        try {
            return this.objectMapper.readValue(livroJson, LivroDTOCadastro.class);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private Livro convertDtoToModel(@Valid LivroDTOCadastro livroDTOCadastro){
        return this.objectMapper.convertValue(livroDTOCadastro, Livro.class);
    }

    public List<Arquivo> convertMultiPartFilesToArquivos(List<MultipartFile> multipartFiles){
        try {
            ArrayList<Arquivo> arquivos = new ArrayList<>();
            for (MultipartFile file : multipartFiles) {
                Arquivo arquivo = new Arquivo();
                arquivo.setNome(file.getOriginalFilename());
                arquivo.setTipo(file.getContentType());
                arquivo.setDados(file.getBytes());
                arquivos.add(arquivo);
            }
            return arquivos;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
