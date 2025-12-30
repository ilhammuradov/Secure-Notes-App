package com.secure.notesapp.controller;

import com.secure.notesapp.model.AuditLog;
import com.secure.notesapp.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("api/audit")
public class AuditLogController {

    private final AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getAuditLogs() {
        return auditLogService.getAllAuditLogs();
    }

    @GetMapping("/note/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public List<AuditLog> getNoteAuditLogs(@PathVariable long id) {
        return auditLogService.getAuditLogsForNoteId(id);
    }
}
