# main.py
from fastapi import FastAPI, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from models import VulnerabilityRecord, DBVulnerabilityRecord
from database import engine, Base, get_db, SessionLocal
from fastapi.responses import RedirectResponse
import sandbox_manager
import exploit_engine

# Create the database tables automatically on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AutoSecTwin Orchestrator")

@app.get("/")
def home():
    return RedirectResponse(url="/docs")

def run_sandbox_and_exploit_task(vuln_id: int, vuln_data: VulnerabilityRecord):
    """Background task to handle the slow pipeline steps."""
    # 1. Provision the sandbox
    container_id, network_name = sandbox_manager.provision_sandbox(vuln_data)
    
    # 2. Trigger the exploit engine 
    exploit_success = exploit_engine.run_exploit(vuln_data, target_network=network_name)
    
    # 3. Update database status 
    db = SessionLocal() # Open a fresh DB session for the background task
    try:
        db_record = db.query(DBVulnerabilityRecord).filter(DBVulnerabilityRecord.id == vuln_id).first()
        if db_record:
            # Update pipeline status based on empirical outcome[cite: 1]
            db_record.pipeline_status = "exploited" if exploit_success else "exploit_failed"
            db.commit()
            print(f"\nPipeline complete. DB Status permanently updated to: {db_record.pipeline_status}.")
    finally:
        db.close()

@app.post("/scan/{target}")
async def start_pipeline(target: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Starts the pipeline and saves the finding to PostgreSQL."""
    
    # 1. Mock data from Phase 1 Scanner[cite: 1]
    vuln_data = VulnerabilityRecord(
        cve_id="CVE-2021-44228", title="Log4j RCE", description="Remote code execution vulnerability.",
        service="Apache", port=8080, host=target
    )
    
    # 2. Save new finding to Postgres Database using shared schema[cite: 1]
    db_record = DBVulnerabilityRecord(
        cve_id=vuln_data.cve_id, title=vuln_data.title, description=vuln_data.description,
        service=vuln_data.service, port=vuln_data.port, host=vuln_data.host,
        pipeline_status="scanned"
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    
    # 3. Pass the DB ID to the background task
    background_tasks.add_task(run_sandbox_and_exploit_task, db_record.id, vuln_data)
    
    return {"message": f"Pipeline started for {target}. DB Record ID: {db_record.id} created.", "status": "scanned"}