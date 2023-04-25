package br.senai.sc.editoralivros.util;

import br.senai.sc.editoralivros.model.entity.*;
import br.senai.sc.editoralivros.model.enums.Genero;
import br.senai.sc.editoralivros.model.enums.Status;
import br.senai.sc.editoralivros.repository.EditoraRepository;
import br.senai.sc.editoralivros.repository.LivroRepository;
import br.senai.sc.editoralivros.repository.PessoaRepository;
import com.github.javafaker.Faker;
import com.itextpdf.text.Document;
import com.itextpdf.text.Paragraph;
import com.itextpdf.text.pdf.PdfWriter;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import javax.annotation.PostConstruct;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

@Component
@AllArgsConstructor
@NoArgsConstructor
public class BancoUtil {

    @Autowired
    private PessoaRepository pessoaRepository;
    @Autowired
    private LivroRepository livroRepository;
    @Autowired
    private EditoraRepository editoraRepository;

    private static Pessoa gerarPessoa(Pessoa pessoa, Editora editora) {
        pessoa.setCpf(Long.parseLong(Faker.instance().numerify("###########")));
        pessoa.setNome(Faker.instance().name().firstName());
        pessoa.setSobrenome(Faker.instance().name().lastName());
        pessoa.setEmail(
                pessoa.getNome().toLowerCase() + "." + pessoa.getSobrenome().toLowerCase() + "@" + editora.getNome().toLowerCase().replaceAll("\\s+", "") + ".com");//Faker.instance().internet().emailAddress());
        pessoa.setSenha("123");//Faker.instance().internet().password());
        pessoa.setGenero(Faker.instance().random().nextBoolean() ? Genero.MASCULINO :
                Faker.instance().random().nextBoolean() ? Genero.FEMININO : Genero.OUTRO);
        return pessoa;
    }

    private static Livro gerarLivro(Status status, Autor autor, Revisor revisor, Editora editora, Arquivo arquivo) {
        Livro livro = new Livro();
        livro.setIsbn(Long.parseLong(Faker.instance().numerify("##############")));
        livro.setTitulo(arquivo.getNome());
        livro.setAutor(autor);
        livro.setQtdPag(Faker.instance().random().nextInt(100, 1000));
        livro.setRevisor(revisor);
        livro.setStatus(status);
        if (livro.getStatus().ordinal() < 2) {
            livro.setPagRevisadas(0);
        } else if (livro.getStatus().ordinal() == 2) {
            livro.setPagRevisadas(Faker.instance().random().nextInt(1, livro.getQtdPag()));
        } else {
            livro.setPagRevisadas(livro.getQtdPag());
        }
        livro.setEditora(editora);
        livro.setArquivos(List.of(arquivo));
        return livro;
    }

    private static Arquivo gerarArquivo() {
        try {
            Arquivo arquivo = new Arquivo();
            arquivo.setNome(Faker.instance().book().title());
            arquivo.setTipo("application/pdf");
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            Document document = new Document();
            PdfWriter.getInstance(document, outputStream);
            document.open();
            document.addTitle(Faker.instance().book().title());
            document.add(new Paragraph(arquivo.getNome()));
            document.close();
            arquivo.setDados(outputStream.toByteArray());
            return arquivo;
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }

    private static Editora geradorEditora() {
        Editora editora = new Editora();
        editora.setCnpj(Long.parseLong(Faker.instance().numerify("##############")));
        editora.setNome(Faker.instance().company().name());
        return editora;
    }

    @PostConstruct
    public void inserirDados() {
        List<Pessoa> pessoas = new ArrayList<>();
        List<Livro> livros = new ArrayList<>();
        List<Arquivo> arquivos = new ArrayList<>();
        List<Status> status = List.of(Status.values());
        Editora editora = geradorEditora();
        Diretor diretor = (Diretor) gerarPessoa(new Diretor(), editora);
        pessoas.add(diretor);
        Revisor revisor1 = (Revisor) gerarPessoa(new Revisor(), editora);
        pessoas.add(revisor1);
        Revisor revisor2 = (Revisor) gerarPessoa(new Revisor(), editora);
        pessoas.add(revisor2);
        for (int i = 0; i < 6; i++) {
            Autor autor = (Autor) gerarPessoa(new Autor(), editora);
            pessoas.add(autor);
        }
        for (int i = 0; i < 36; i++) {
            Arquivo arquivo = gerarArquivo();
            arquivos.add(arquivo);
        }
        for (int i = 3, j = 0; i < 9; i++) {
            for (int k = 0; k < 6; k++, j++) {
                Livro livro;
                if (status.get(k).ordinal() < 2) {
                    livro = gerarLivro(status.get(k), (Autor) pessoas.get(i), null, null, arquivos.get(j));
                } else if (status.get(k).ordinal() == 2) {
                    Revisor revisor = Faker.instance().random().nextBoolean() ? revisor1 : revisor2;
                    livro = gerarLivro(status.get(k), (Autor) pessoas.get(i), revisor, null, arquivos.get(j));
                } else {
                    Revisor revisor = Faker.instance().random().nextBoolean() ? revisor1 : revisor2;
                    livro = gerarLivro(status.get(k), (Autor) pessoas.get(i), revisor, editora, arquivos.get(j));
                }
                arquivos.get(j).setLivro(livro);
                livros.add(livro);
            }
        }

            Diretor admin = new Diretor();
            admin.setCpf(Long.parseLong(Faker.instance().numerify("08631738964")));
            admin.setNome("Admin");
            admin.setSobrenome("");
            admin.setEmail("admin@admin");//Faker.instance().internet().emailAddress());
            admin.setSenha("123");//Faker.instance().internet().password());
            admin.setGenero(Genero.MASCULINO);
            pessoas.add(admin);
        editoraRepository.save(editora);
        pessoaRepository.saveAll(pessoas);
        livroRepository.saveAll(livros);
    }
}
