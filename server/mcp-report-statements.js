export function prepareMcpReportStatements(db) {
  return {
    mcpProjects: db.prepare(`
      SELECT projects.id, json_extract(projects.data, '$.name') AS name,
        (SELECT count(*) FROM findings
          WHERE owner_id = projects.owner_id AND project_id = projects.id) AS findingCount
      FROM projects
      WHERE projects.owner_id = ?
      ORDER BY projects.id
    `),
    mcpFindingSummaries: db.prepare(`
      SELECT id, json_extract(data, '$.title') AS title,
        json_extract(data, '$.severity') AS severity,
        json_extract(data, '$.status') AS status,
        json_extract(data, '$.createdAt') AS createdAt,
        json_extract(data, '$.confidence') AS confidence,
        json_extract(data, '$.templateId') AS templateId,
        json_extract(data, '$.category') AS category
      FROM findings
      WHERE owner_id = @ownerId AND project_id = @projectId
        AND (@severity IS NULL OR json_extract(data, '$.severity') = @severity)
        AND (@status IS NULL OR json_extract(data, '$.status') = @status)
        AND (@query IS NULL OR instr(lower(concat_ws(' ', id,
          json_extract(data, '$.title'), json_extract(data, '$.category'),
          json_extract(data, '$.tags'), json_extract(data, '$.templateId'),
          json_extract(data, '$.url'), json_extract(data, '$.affectedHost'),
          json_extract(data, '$.cwe'), json_extract(data, '$.cve'),
          json_extract(data, '$.targets')
        )), lower(@query)) > 0)
      ORDER BY createdAt DESC, id
      LIMIT @limit OFFSET @offset
    `),
    mcpFinding: db.prepare('SELECT data FROM findings WHERE owner_id = ? AND project_id = ? AND id = ?'),
    mcpUpdateFinding: db.prepare(`
      UPDATE findings SET data = json_patch(data, @patch)
      WHERE owner_id = @ownerId AND project_id = @projectId AND id = @findingId
    `),
  };
}
