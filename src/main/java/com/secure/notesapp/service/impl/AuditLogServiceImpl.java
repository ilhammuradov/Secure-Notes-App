package com.secure.notesapp.service.impl;

import com.secure.notesapp.model.AuditAction;
import com.secure.notesapp.model.AuditLog;
import com.secure.notesapp.model.Note;
import com.secure.notesapp.repository.AuditLogRepository;
import com.secure.notesapp.service.AuditLogService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepository;

   // String username = SecurityContextHolder.getContext().getAuthentication().getName();

    private AuditLog buildLog(String username, AuditAction action, Long noteId, String content) {
        AuditLog log = new AuditLog();
        log.setAction(action);
        log.setUsername(username);
        log.setNoteId(noteId);
        log.setNoteContent(content);
        log.setTimestamp(LocalDateTime.now());
        return log;
    }

    @Override
    public void logNoteCreation(String user, Note note) {
        auditLogRepository.save(
                buildLog(user, AuditAction.CREATE, note.getId(), note.getContent())
        );
    }

    @Override
    public void logNoteUpdate(String user, Note note) {
        auditLogRepository.save(
                buildLog(user, AuditAction.UPDATE, note.getId(), note.getContent())
        );
    }

    @Override
    public void logNoteDeletion(String user, Long noteId) {
        auditLogRepository.save(
                buildLog(user, AuditAction.DELETE, noteId, null)
        );
    }

    @Override
    public List<AuditLog> getAllAuditLogs() {
        return auditLogRepository.findAll();
    }

    @Override
    public List<AuditLog> getAuditLogsForNoteId(Long id) {
        return auditLogRepository.findByNoteId(id);
    }
}
