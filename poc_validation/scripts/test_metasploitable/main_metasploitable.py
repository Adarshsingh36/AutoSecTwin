from fastapi import FastAPI, BackgroundTasks, Depends
from sqlalchemy.orm import Session
from models import VulnerabilityRecord, DBVulnerabilityRecord
from database import engine, Base, get_db, SessionLocal
from fastapi.responses import RedirectResponse
import sandbox_manager_metasploitable as sandbox_manager
import exploit_engine

Base.metadata.create_all(bind=engine)
app = FastAPI(title="AutoSecTwin Orchestrator - Metasploitable Test")

@app.get("/")
def home():
    return RedirectResponse(url="/docs")

def run_sandbox_and_exploit_task(vuln_id: int, vuln_data: VulnerabilityRecord):
    container_id, network_name = sandbox_manager.provision_sandbox(vuln_data)
    exploit_success = exploit_engine.run_exploit(vuln_data, target_network=network_name)
    
    db = SessionLocal()
    try:
        db_record = db.query(DBVulnerabilityRecord).filter(DBVulnerabilityRecord.id == vuln_id).first()
        if db_record:
            db_record.pipeline_status = "exploited" if exploit_success else "exploit_failed"
            db.commit()
            print(f"\n[Metasploitable] Status permanently updated to: {db_record.pipeline_status}")
    finally:
        db.close()

@app.post("/scan/{target}")
async def start_pipeline(target: str, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    vuln_data = VulnerabilityRecord(
        cve_id="CVE-2015-3306",
        title="ProFTPD Mod_Copy RCE",
        description="Remote code execution in ProFTPD 1.3.5.",
        service="ProFTPD",
        port=21,
        host=target
    )
    
    db_record = DBVulnerabilityRecord(
        cve_id=vuln_data.cve_id, title=vuln_data.title, description=vuln_data.description,
        service=vuln_data.service, port=vuln_data.port, host=vuln_data.host,
        pipeline_status="scanned"
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)
    
    background_tasks.add_task(run_sandbox_and_exploit_task, db_record.id, vuln_data)
    return {"message": f"Pipeline started for Metasploitable on {target}.", "status": "scanned"}