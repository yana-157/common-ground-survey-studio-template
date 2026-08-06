import { createClient } from "@supabase/supabase-js";

const projectUrl = process.env.SUPABASE_CLEANUP_URL?.trim();
const adminKey = process.env.SUPABASE_ADMIN_KEY?.trim();
const batchSize = 100;
const maxPasses = 20;

if (!projectUrl || !adminKey) {
  throw new Error("Survey cleanup requires SUPABASE_CLEANUP_URL and SUPABASE_ADMIN_KEY.");
}

const supabase = createClient(projectUrl, adminKey, {
  auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
});

let deletedCount = 0;

for (let pass = 0; pass < maxPasses; pass += 1) {
  const dueResult = await supabase.rpc("list_due_survey_deletions", { p_limit: batchSize });
  if (dueResult.error) throw new Error(`List surveys due for deletion: ${dueResult.error.message}`);
  const dueSurveys = Array.isArray(dueResult.data) ? dueResult.data : [];
  if (!dueSurveys.length) break;

  for (const survey of dueSurveys) {
    const uploadObjects = Array.isArray(survey.upload_objects) ? survey.upload_objects : [];
    const pathsByBucket = new Map();
    for (const upload of uploadObjects) {
      if (!upload || typeof upload.bucket_id !== "string" || typeof upload.object_path !== "string") {
        throw new Error(`Survey ${survey.survey_id ?? "unknown"} returned invalid upload metadata; no database records were purged.`);
      }
      const paths = pathsByBucket.get(upload.bucket_id) ?? new Set();
      paths.add(upload.object_path);
      pathsByBucket.set(upload.bucket_id, paths);
    }

    for (const [bucketId, pathSet] of pathsByBucket) {
      const paths = [...pathSet];
      for (let offset = 0; offset < paths.length; offset += 100) {
        const removal = await supabase.storage.from(bucketId).remove(paths.slice(offset, offset + 100));
        if (removal.error) {
          throw new Error(`Delete response uploads for survey ${survey.survey_id ?? "unknown"}: ${removal.error.message}. Database records were not purged.`);
        }
      }
    }
  }

  const purgeResult = await supabase.rpc("purge_due_deleted_surveys", { p_limit: batchSize });
  if (purgeResult.error) throw new Error(`Purge due survey records: ${purgeResult.error.message}`);
  const purged = Array.isArray(purgeResult.data) ? purgeResult.data : [];
  if (!purged.length) {
    throw new Error("No due survey could be purged after its uploads were removed. The database kept all remaining records; inspect the cleanup workflow before retrying.");
  }
  deletedCount += purged.length;
}

const remainingResult = await supabase.rpc("list_due_survey_deletions", { p_limit: 1 });
if (remainingResult.error) throw new Error(`Confirm survey cleanup: ${remainingResult.error.message}`);
if (Array.isArray(remainingResult.data) && remainingResult.data.length) {
  throw new Error(`Cleanup stopped after ${maxPasses * batchSize} surveys. Run the workflow again to continue.`);
}

console.log(deletedCount ? `Permanently deleted ${deletedCount} survey${deletedCount === 1 ? "" : "s"} whose 30-day recovery windows had ended.` : "No surveys were due for permanent deletion.");
